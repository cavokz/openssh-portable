#	$OpenBSD: keytype.sh,v 1.10 2019/12/16 02:39:05 djm Exp $
#	Placed in the Public Domain.

tid="login with different key types"

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak
cp $OBJ/ssh_proxy $OBJ/ssh_proxy_bak

. $OBJ/keytype_gen.sh

tries="1 2 3"
for ut in $ktypes; do
	user_type=`kname_to_ktype "$ut"`
	htypes="$ut"
	#htypes=$ktypes
	for ht in $htypes; do
		host_type=`kname_to_ktype "$ht"`
		trace "ssh connect, userkey $ut, hostkey $ht"
		(
			grep -v HostKey $OBJ/sshd_proxy_bak
			echo HostKey $OBJ/key.$ht
			echo PubkeyAcceptedKeyTypes $user_type
			echo HostKeyAlgorithms $host_type
		) > $OBJ/sshd_proxy
		(
			grep -v IdentityFile $OBJ/ssh_proxy_bak
			echo IdentityFile $OBJ/key.$ut
			echo PubkeyAcceptedKeyTypes $user_type
			echo HostKeyAlgorithms $host_type
		) > $OBJ/ssh_proxy
		(
			printf 'localhost-with-alias,127.0.0.1,::1 '
			cat $OBJ/key.$ht.pub
		) > $OBJ/known_hosts
		cat $OBJ/key.$ut.pub > $OBJ/authorized_keys_$USER
		for i in $tries; do
			verbose "userkey $ut, hostkey ${ht}"
			${SSH} -F $OBJ/ssh_proxy 999.999.999.999 true
			if [ $? -ne 0 ]; then
				fail "ssh userkey $ut, hostkey $ht failed"
			fi
		done
	done
done
