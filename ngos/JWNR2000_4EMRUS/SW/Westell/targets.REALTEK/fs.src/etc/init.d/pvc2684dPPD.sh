#!/bin/sh

until [ -z "$1" ]
do
case $1 in
	-pre)
# Put your pre processing code here
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

