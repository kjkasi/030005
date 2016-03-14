#!/bin/sh
#Delete Original Vci/Vpi number 0.x.x
        echo $1

        /sbin/ifconfig nas0 0.0.0.0 down
        /bin/pvc2684ctl -d -i 0 -v $1
#       /bin/atmctl operate vcc --deleteq $1 128 1 --delete $1 
