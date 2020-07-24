/*
 * Copyright (c) 2020 Domenico Andreoli
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <string.h>
#include <syslog.h>

#define PAM_SM_AUTH
#if defined(HAVE_SECURITY_PAM_MODULES_H)
#include <security/pam_modules.h>
#elif defined(HAVE_PAM_PAM_MODULES_H)
#include <pam/pam_modules.h>
#endif

#include "authfile.h"
#include "authfd.h"
#include "ssherr.h"
#include "sshkey.h"
#include "ssh.h"

static int pam_debug;
static const char *auth_file;

static int
parse_args(int argc, const char **argv)
{
	int i, invalid = 0;

	for (i=0; i!=argc; i++) {
		if (!strcmp(argv[i], "debug")) {
			pam_debug = 1;
		} else if (!strncmp(argv[i], "file=", 5)) {
			if (argv[i][5] == '\0')
				continue;
			auth_file = argv[i] + 5;
			if (auth_file[0] != '/') {
				syslog(LOG_ERR, "auth file error: Path is not absolute: %s", auth_file);
				invalid++;
			}
		} else {
			syslog(LOG_ERR, "invalid argument: %s", argv[i]);
			invalid++;
		}
	}

	return invalid;
}

static int
ssh_read_identitylist(const char *filename, struct ssh_identitylist **idlp)
{
	struct ssh_identitylist *idl = NULL;
	int r;

	if ((idl = calloc(1, sizeof(*idl))) == NULL ||
	    (idl->keys = calloc(1, sizeof(*idl->keys))) == NULL ||
	    (idl->comments = calloc(1, sizeof(*idl->comments))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	r = sshkey_load_public(filename, &idl->keys[0], &idl->comments[0]);
	if (r)
		goto out;

	idl->nkeys = 1;
	*idlp = idl;
	idl = NULL;

out:
	if (idl != NULL)
		ssh_free_identitylist(idl);
	return r;
}

static int
challenge_agent(int agent_fd, const struct sshkey *agent_key, const struct sshkey *auth_key)
{
	u_char *sig = NULL;
	size_t slen = 0;
	char data[1024];
	int ret;

	arc4random_buf(data, sizeof(data));
	ret = ssh_agent_sign(agent_fd, agent_key, &sig, &slen, data, sizeof(data), NULL, 0) ||
	      sshkey_verify(auth_key, sig, slen, data, sizeof(data), NULL, 0, NULL);

	if (sig != NULL)
		free(sig);
	return !ret;
}

static int
authenticate_agent(int agent_fd, const struct ssh_identitylist *agent_ids,
	const struct ssh_identitylist *auth_ids)
{
	unsigned i, j;
	for (i=0; i!=agent_ids->nkeys; i++)
		for (j=0; j!=auth_ids->nkeys; j++)
			if (sshkey_equal(agent_ids->keys[i], auth_ids->keys[j]))
				if (challenge_agent(agent_fd, agent_ids->keys[i], auth_ids->keys[j]))
					return PAM_SUCCESS;
	return PAM_AUTH_ERR;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	struct ssh_identitylist *agent_ids = NULL;
	struct ssh_identitylist *auth_ids = NULL;
	int agent_fd = -1;
	int ret;

	openlog("pam_ssh_agent_auth", 0, LOG_AUTHPRIV);

	if (parse_args(argc, argv)) {
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	if (pam_debug) {
		const char *auth_socket = getenv(SSH_AUTHSOCKET_ENV_NAME);
		const char *user = "(unknown)";
		pam_get_user(pamh, &user, NULL);
		syslog(LOG_DEBUG, "USER: %s", user);
		syslog(LOG_DEBUG, "FILE: %s", auth_file ? auth_file : "(null)");
		auth_socket = auth_socket ? auth_socket : "(null)";
		syslog(LOG_DEBUG, "%s: %s", SSH_AUTHSOCKET_ENV_NAME, auth_socket);
	}

	if (auth_file == NULL) {
		syslog(LOG_ERR, "auth file error: file= is not specified");
		ret = PAM_SERVICE_ERR;
		goto out;
	}

	ret = ssh_read_identitylist(auth_file, &auth_ids);
	if (ret) {
		syslog(LOG_ERR, "auth file error: %s: %s", ssh_err(ret), auth_file);
		ret = PAM_AUTHINFO_UNAVAIL;
		goto out;
	}

	if (pam_debug) {
		unsigned i;
		syslog(LOG_DEBUG, "auth file has %u key(s):", (unsigned) auth_ids->nkeys);
		for (i=0; i!=auth_ids->nkeys; i++)
			syslog(LOG_DEBUG, "  %d) %s", i, auth_ids->comments[i]);
	}

	ret = ssh_get_authentication_socket(&agent_fd);
	if (ret) {
		syslog(LOG_NOTICE, "agent error: %s", ssh_err(ret));
		ret = PAM_AUTH_ERR;
		goto out;
	}

	ret = ssh_fetch_identitylist(agent_fd, &agent_ids);
	if (ret) {
		syslog(LOG_NOTICE, "agent error: %s", ssh_err(ret));
		ret = PAM_AUTH_ERR;
		goto out;
	}

	if (pam_debug) {
		unsigned i;
		syslog(LOG_DEBUG, "agent has %u key(s):", (unsigned) agent_ids->nkeys);
		for (i=0; i!=agent_ids->nkeys; i++)
			syslog(LOG_DEBUG, "  %d) %s", i, agent_ids->comments[i]);
	}

	ret = authenticate_agent(agent_fd, agent_ids, auth_ids);

out:
	if (agent_fd != -1)
		ssh_close_authentication_socket(agent_fd);
	if (agent_ids != NULL)
		ssh_free_identitylist(agent_ids);
	if (auth_ids != NULL)
		ssh_free_identitylist(auth_ids);
	if (pam_debug)
		syslog(LOG_DEBUG, "result: %s", pam_strerror(pamh, ret));
	closelog();
	return ret;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return PAM_SUCCESS;
}
