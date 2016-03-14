#!/bin/sh
pipecmd='/tmp/dsl_pipe.sh'

cat >$pipecmd <<EOF
#!/bin/sh

pipe_no=0

echo \$* > /tmp/pipe/dsl_cpe\${pipe_no}_cmd
result=\`cat /tmp/pipe/dsl_cpe\${pipe_no}_ack\`

echo "\$result"
EOF

chmod 0755 $pipecmd

wa()
{
	$pipecmd dms 00A1 0000 0003 C0E8 $1
	$pipecmd dms 00A1 0000 0003 1F48 0020
	$pipecmd dms 00A1 0000 0003 C0F0 $2
	
	result="0000"
	
	until [ $result = '0030' ]
	do
		result=`$pipecmd dms 0021 0000 0003 1F48 0000 | cut -d \" -f 2 | grep 0x | cut -c 3-6`
	done
}

$pipecmd alf . .; $pipecmd alf . ; $pipecmd acs 0

$pipecmd cw cntl 0 0 8

wa 2 0

$pipecmd cw test 7 0 4
$pipecmd cw test 7 0 1

wa 6 15
wa 7 D03

$pipecmd cw test 7 0 4
$pipecmd cw test 7 0 6
$pipecmd cw test 7 0 2

wa 5 1A0D

$pipecmd cw test 6 0 0

$pipecmd cw test 6 0 1

echo "sleeping for 15 seconds"
sleep 15

echo "To Stop Full Tx Mode, issue the command:"
echo " /etc/InfineonScripts/dsl_cpe_pipe.sh cw test 6 0 0"
echo " "
echo "To Stop the FW, issue the command:"
echo " /etc/InfineonScripts/dsl_cpe_pipe.sh acs 0"
echo " "
echo "To Restart G.hs, issue the command:"
echo " /etc/InfineonScripts/dsl_cpe_pipe.sh acs 2"
