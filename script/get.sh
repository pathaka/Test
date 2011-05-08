#!/bin/sh

root=$1
src_file=$2
tmp_file=tmp.pathneck

$root/script/get.pl $root $src_file > $tmp_file
$root/script/get-summary.pl $tmp_file
cat $tmp_file
