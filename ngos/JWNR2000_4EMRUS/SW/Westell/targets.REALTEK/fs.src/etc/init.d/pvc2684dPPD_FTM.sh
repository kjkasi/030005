#!/bin/sh

until [ -z "$1" ]
do
case $1 in
	-pre)
# Put your pre processing code here
#enable the interfaces
       	ifconfig eth0 hw ether `cfg_read -q ProductionData.0.MacAddr`
        ifconfig eth0 0.0.0.0 up
#       ifconfig usb0 0.0.0.0 up
#       ifconfig eth1 hw ether 00:60:0f:00:00:02
       	ifconfig eth1 hw ether `cfg_read -q ProductionData.0.MacAddr`
        ifconfig eth1 0.0.0.0 up
       	ifconfig eth2 hw ether `cfg_read -q ProductionData.0.MacAddr`
        ifconfig eth2 0.0.0.0 up
       	ifconfig eth3 hw ether `cfg_read -q ProductionData.0.MacAddr`
        ifconfig eth3 0.0.0.0 up
       	ifconfig eth4 hw ether `cfg_read -q ProductionData.0.MacAddr`
        ifconfig eth4 0.0.0.0 up
       	ifconfig wlan0 0.0.0.0 down
	ifconfig wlan0 hw ether `cfg_read -q ProductionData.0.MacAddr`
	ifconfig wlan0 0.0.0.0 up

#	ifconfig ath0 0.0.0.0 up
# create the bridge
        brctl addbr br0
# add interfaces to the bridge
        brctl addif br0 eth0
        brctl addif br0 eth1
        brctl addif br0 eth2
        brctl addif br0 eth3
        brctl addif br0 eth4
#       brctl addif br0 usb0
        brctl addif br0 wlan0
#        brctl addif br0 ath0
        brctl setfd br0 2
#       ifconfig br0 192.168.1.1 up
        ifconfig br0 $ipaddr up
	sleep 5

#start the DSL driver
#	adslctl start
#	adslctl connection --up

#start the ATM interface
#	atmctl start
#	atmctl operate intf --state 0 enable

	;;

	-post)
# Put your post processing code here

	;;

	-death)
# Put your death processing code here

#    atmctl operate intf --state 0 disable
#    atmctl stop
#    adslctl connection --down
#    adslctl stop
	
	;;

	-restart)
# Put your restart processing code here

	;;

	*)
# If you passed your own parameters, put processing code here
# or add additional handlers above

	;;

esac
shift
done

