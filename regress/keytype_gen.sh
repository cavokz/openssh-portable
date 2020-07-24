#	$OpenBSD: keytype.sh,v 1.10 2019/12/16 02:39:05 djm Exp $
#	Placed in the Public Domain.

# Construct list of key types based on what the built binaries support.
ktypes=""
for i in ${SSH_KEYTYPES}; do
	case "$i" in
		ssh-dss)		ktypes="$ktypes dsa-1024" ;;
		ssh-rsa)		ktypes="$ktypes rsa-2048 rsa-3072" ;;
		ssh-ed25519)		ktypes="$ktypes ed25519-512" ;;
		ecdsa-sha2-nistp256)	ktypes="$ktypes ecdsa-256" ;;
		ecdsa-sha2-nistp384)	ktypes="$ktypes ecdsa-384" ;;
		ecdsa-sha2-nistp521)	ktypes="$ktypes ecdsa-521" ;;
		sk-ssh-ed25519*)	ktypes="$ktypes ed25519-sk" ;;
		sk-ecdsa-sha2-nistp256*) ktypes="$ktypes ecdsa-sk" ;;
	esac
done

for kt in $ktypes; do
	rm -f $OBJ/key.$kt
	xbits=`echo ${kt} | awk -F- '{print $2}'`
	xtype=`echo ${kt}  | awk -F- '{print $1}'`
	case "$kt" in
	*sk)	type="$kt"; bits="n/a"; bits_arg="";;
	*)	type=$xtype; bits=$xbits; bits_arg="-b $bits";;
	esac
	verbose "keygen $type, $bits bits"
	${SSHKEYGEN} $bits_arg -q -N '' -t $type -C "$kt" -f $OBJ/key.$kt || \
		fail "ssh-keygen for type $type, $bits bits failed"
done

kname_to_ktype() {
	case $1 in
	dsa-1024)	echo ssh-dss;;
	ecdsa-256)	echo ecdsa-sha2-nistp256;;
	ecdsa-384)	echo ecdsa-sha2-nistp384;;
	ecdsa-521)	echo ecdsa-sha2-nistp521;;
	ed25519-512)	echo ssh-ed25519;;
	rsa-*)		echo rsa-sha2-512,rsa-sha2-256,ssh-rsa;;
	ed25519-sk)	echo sk-ssh-ed25519@openssh.com;;
	ecdsa-sk)	echo sk-ecdsa-sha2-nistp256@openssh.com;;
	esac
}
