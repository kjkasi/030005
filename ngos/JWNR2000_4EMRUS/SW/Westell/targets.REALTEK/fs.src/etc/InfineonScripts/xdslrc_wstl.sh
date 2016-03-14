#!/bin/sh

# This script has been enhanced to handle the XDSL Events for Multimode FSM
# and subsequent DSL Link bringup handling.

ptmfile=/WFIO/PTM_MODE

if [ -f $ptmfile ]; then
   echo "Last mode was PTM"
   Next_xTM_Mode="PTM"
else
   echo "Last mode was ATM"
   Next_xTM_Mode="ATM"
fi

neg_xdsl_mode="ADSL"
xTM_Mgmt_Mode="Auto"

# DSL Event handling script - Triggered from DSL CPE control Application
case "$DSL_NOTIFICATION_TYPE" in
	DSL_STATUS)
	# Handles the DSL Link Bringup sequence

		echo "DSL_STATUS Notification"

		# For Negotiated xDSL Mode as "ADSL", check on the TC Layer for ATM (or) PTM
		if [ "$neg_xdsl_mode" = "ADSL" ]; then
			if [ "$DSL_TC_LAYER_STATUS" = "ATM" -a "$Next_xTM_Mode" = "ATM" ] || 
    	         [ "$DSL_TC_LAYER_STATUS" = "EFM" -a "$Next_xTM_Mode" = "PTM" ]; then
				# EVERYTHING MATCHES - Do nothing as we have already inserted & started the DSL SM with 
				# the correct parameters
				echo -n
			else
				if [ "$xTM_Mgmt_Mode" = "Auto" ]; then
					echo "neg_xdsl_mode = $neg_xdsl_mode, Next_xTM_Mode = $Next_xTM_Mode DSL_TC_LAYER_STATUS = $DSL_TC_LAYER_STATUS"
					# Save the Trained xTM Mode along with negotiated xDSL Mode and
					# set the SW Forced Reboot flag to true
					# Update the configuration in flash and reboot to restart the DSL
					# FSM over again. 

					# Update Next_xTM_Mode(DSL_TC_LAYER_STATUS), xDSL_SW_Forced_Reboot(true=1)
					# and Next_xDSL_Mode(ADSL=1) in flash
					if [ "$DSL_TC_LAYER_STATUS" = "EFM" ]; then
						neg_xTM_Mode="PTM"
                  echo "1" > $ptmfile
					elif [ "$DSL_TC_LAYER_STATUS" = "ATM" ]; then
						neg_xTM_Mode="ATM"
						rm -f $ptmfile
					else 
						echo "neg_xTM_Mode = $DSL_TC_LAYER_STATUS "
					fi

					# Reboot the CPE with the modified values
					# These new values will take effect on DSL bringup
               echo "Need to reboot to set new mode"
               # Sleep to allow WFIO to flush
               sleep 5
					/bin/reboot
				else
					echo "$DSL_TC_LAYER_STATUS not supported for $xTM_Mgmt_Mode Management Mode"
				fi
			fi
		fi
	echo "xDSL Mode = $DSL_XTU_STATUS"
	echo "DSL TC Mode = $DSL_TC_LAYER_STATUS"
	;;

	DSL_INTERFACE_STATUS)
	case "$DSL_INTERFACE_STATUS" in 
	"UP")
		# DSL link up trigger
		echo "xDSL Enter SHOWTIME!!"

		# Adjust the upstream/downstream rates of the queues created in the system
		UPSTREAM_RATE=$(( $DSL_DATARATE_US_BC0 / 1000 ))
		#echo "US Rate $UPSTREAM_RATE kbps"
		DOWNSTREAM_RATE=$(( $DSL_DATARATE_DS_BC0 / 1000 ))
		#echo "DS Rate $DOWNSTREAM_RATE kbps"
		;;

	"DOWN")
		# DSL link down trigger
		echo "xDSL Leave SHOWTIME!!"
		;;

	"READY")
		#echo "xDSL Handshake!!"
		;;

	"TRAINING")
		#echo "xDSL Training !!"
		;;
	esac
	;;

	DSL_DATARATE_STATUS)
	echo "DSL US Data Rate = "`expr $DSL_DATARATE_US_BC0 / 1000`" kbps"
	echo "DSL DS Data Rate = "`expr $DSL_DATARATE_DS_BC0 / 1000`" kbps"
	;;

	DSL_DATARATE_STATUS_US)
	echo "DSL US Data Rate = "$(( $DSL_DATARATE_US_BC0 / 1000 ))" kbps"
	;;

	DSL_DATARATE_STATUS_DS)
	echo "DSL DS Data Rate = "$(( $DSL_DATARATE_DS_BC0 / 1000 ))" kbps"
	;;
esac

