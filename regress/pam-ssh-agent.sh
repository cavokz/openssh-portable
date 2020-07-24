#       Placed in the Public Domain.

# Kudos to the Samba team, pam_wrapper made this module possible
#
#   https://cwrap.org/pam_wrapper.html
#   https://lwn.net/Articles/671094/

if [ "x$TEST_PAM_SSH_AGENT" = "xno" ]; then
	verbose "PAM ssh-agent testing is disabled, skipping tests..."
	exit 0
fi

export PAM_WRAPPER_SERVICE_DIR=$OBJ/pam-ssh-agent-test.d

PAM_SUCCESS=0
PAM_SERVICE_ERR=3
PAM_AUTH_ERR=7
PAM_AUTHINFO_UNAVAIL=9

. $OBJ/keytype_gen.sh

first_kt=`echo $ktypes | cut -d" " -f1`
second_kt=`echo $ktypes | cut -d" " -f2`
AUTH_FILE=$OBJ/key.$first_kt.pub
AUTH_FILE2=$OBJ/key.$second_kt.pub

pam_agent_test()
{
	rm -rf $PAM_WRAPPER_SERVICE_DIR
	mkdir -p $PAM_WRAPPER_SERVICE_DIR
	cat >$PAM_WRAPPER_SERVICE_DIR/other <<EOF
auth  required  $BUILDDIR/pam_ssh_agent.so  $*
EOF

	LD_PRELOAD=libpam_wrapper.so \
	PAM_WRAPPER=1 \
	$BUILDDIR/$TEST_PAM_SSH_AGENT

	local ret=$?
	[ "x$ret" = "x$expect" ] || fatal "expected $expect, got $ret"
}

trace "invalid arguments"
expect=$PAM_SERVICE_ERR       pam_agent_test invalid arguments

trace "without arguments"
expect=$PAM_SERVICE_ERR       pam_agent_test # file= is required

trace "with non-absolute auth file path"
expect=$PAM_SERVICE_ERR       pam_agent_test file=nonabsolute.$$

trace "with non-existent auth file"
expect=$PAM_AUTHINFO_UNAVAIL  pam_agent_test file=/nonexistent.$$

trace "with empty auth file"
expect=$PAM_AUTHINFO_UNAVAIL  pam_agent_test file=/dev/null

trace "start agent"
eval `${SSHAGENT} ${EXTRA_AGENT_ARGS} -s` > /dev/null
r=$?
if [ $r -ne 0 ]; then
	fatal "could not start ssh-agent: exit code $r"
fi

trace "load key into the agent"
${SSHADD} -q $OBJ/key.$first_kt
r=$?
if [ $r -ne 0 ]; then
	fatal "could not add the key: exit code $r"
fi

trace "authenticate agent (debug)"
expect=$PAM_SUCCESS           pam_agent_test file=$AUTH_FILE debug

trace "authenticate agent (non-debug)"
expect=$PAM_SUCCESS           pam_agent_test file=$AUTH_FILE

trace "change of auth file (debug)"
expect=$PAM_AUTH_ERR          pam_agent_test file=$AUTH_FILE2 debug

trace "change of auth file (non-debug)"
expect=$PAM_AUTH_ERR          pam_agent_test file=$AUTH_FILE2

for kt in $ktypes; do
	trace "load key $kt into the agent"
	${SSHADD} -q $OBJ/key.$kt
	r=$?
	if [ $r -ne 0 ]; then
		fatal "could not add the key: exit code $r"
	fi

	trace "authenticate agent with $kt (debug)"
	expect=$PAM_SUCCESS       pam_agent_test file=$OBJ/key.$kt.pub debug

	trace "authenticate agent with $kt (non-debug)"
	expect=$PAM_SUCCESS       pam_agent_test file=$OBJ/key.$kt.pub
done

trace "kill agent"
${SSHAGENT} -k > /dev/null

trace "agent is gone (debug)"
expect=$PAM_AUTH_ERR          pam_agent_test file=$AUTH_FILE debug

trace "agent is gone (non-debug)"
expect=$PAM_AUTH_ERR          pam_agent_test file=$AUTH_FILE
