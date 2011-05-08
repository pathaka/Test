#!/bin/sh

##############################################################################
# The "root" line must be set correctly, with the the directory 
# where the source is installed
##############################################################################

root=/home/pathaka/workspace/pathneck-1.3

####################################################
#	Optional configuration below
####################################################

# get the raw data, probe 10 times
for i in 1 2 3 4 5 6 7 8 9 10
do
	$root/pathneck $1 >> $1.txt
	sleep 2
done

# process the raw data: sanity check, bottleneck info, etc
$root/script/get.sh $root $1.txt > $1.sum
