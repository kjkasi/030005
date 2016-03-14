#
# Script to start NAS for VC Search
# $0 <port.VPI.VCI> <MAC-Addr>
# /bin/sh vc-search-start.sh 0.8.35 00.60.0F.44.45.46
/bin/pvc2684ctl -a -i 0  -v ${1} -g vcsearch
/sbin/ifconfig nas0 hw ether ${2}
/sbin/ifconfig nas0 0.0.0.0 up
