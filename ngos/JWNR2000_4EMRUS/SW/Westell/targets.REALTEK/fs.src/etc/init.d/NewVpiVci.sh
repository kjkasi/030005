#!/bin/sh
#Pass in VciVpi string example 0.0.35

#Set Vci/Vpi number
        echo $1 $2
#        atmctl operate vcc --add $1 aal5 1 llcencaps --addq $1 64 1
#        pvc2684ctl -a -i 0 -v $1

#       /bin/atmctl operate vcc --add $1 aal5 1 llcencaps --addq $1 128 1
        /bin/pvc2684ctl -a -i 0 -v $1

#        /bin/atmctl operate vcc --add 0.0.35 aal5 1 llcencaps --addq 0.0.35 64 1
#        /bin/pvc2684ctl -a -i 0 -v 0.0.35

#nas0
        /sbin/ifconfig nas0 hw ether $2
        /sbin/ifconfig nas0 0.0.0.0 up
        /bin/brctl addif br0 nas0
