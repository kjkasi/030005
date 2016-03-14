#/bin/sh
# set_medium_id.sh value
# Sets every /proc/sys/net/ipv4/conf/*/medium_id (except conf/all) to value

ls /proc/sys/net/ipv4/conf/*/medium_id | grep -v "conf/all" | while read name
do
echo $1 > $name
done

