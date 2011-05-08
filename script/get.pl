#!/usr/bin/perl -w

#***************************************************************************
#  Pathneck: locating network path bottlenecks
#  Copyright (C) 2004
#  Ningning Hu and the Carnegie Mellon University
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License (in the COPYING file) for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#***************************************************************************/

if (@ARGV < 2) {
	print "./get.pl <dir-of-get-choke> <input-file>\n";
	exit(0);
}

$code_dir = $ARGV[0];
open(IN, "<$ARGV[1]");

while (<IN>) {
	chomp;
	@F = split;

	if (@F == 0) {
	    next if (!$has_data);

	    &process;

	    $has_data = 0;
	    $has_choke = 0;
	    next;
	}

	# rtt line
	if ($F[0] eq "rtt") {
	    print "$_\n\n";
	    next;
	}

	if ($F[0] =~ /\d+\.\d+/) {
	    print "info $_\n\n";

	    $pkt_size = $F[2];
	    $pkt_num = $F[3];

	    $has_data = 0;
	    @rtt = (); @gaps = (); @ip = (); @hosts = ();
	    @gap1 = (); @choke = ();
	    next;
	}

	if (/conf/) {
	    $conf_line = $_;
	}

	if ($F[0] =~ /^\d\d$/ && $F[1] =~ /^\d+\.\d+$/ && 
	    $F[2] =~ /^\d+\.\d+\.\d+\.\d+$/) {
	    # the data line	
	    $has_data = 1;

	    $rtt[@rtt] = $F[1];
	    $gaps[@gaps] = $F[3];
	    $ip[@ip] = $F[2];

	    # deal with "-o" options
	    if (@F >= 8) {
	        # -o || -xo
	        $has_choke = 1;
		$gap1[@gap1] = $F[4];
		$choke[@choke] = $F[5];

		$bw[@bw] = $F[6];
		$bw_flag[@bw_flag] = $F[7];
	    }

	    # deal with hostname
	    if (@F == 5 || @F == 9) {
	        # -x    || -xo
	    	$hosts[@hosts] = $F[$#F];
	    } else {
	        # no options 
	    	$hosts[@hosts] = $F[2];
	    }
	}
}

sub process {
	local(*IN2);
	local ($i);

	# the data are already processed, just dump it in the 
	# readable format for get-summary.pl
	if ($has_choke) {
	    for $i (0..$#gaps) {
		if ($choke[$i] eq ".") {
	        	$choke[$i] = " ";
		} else {
	        	$choke[$i] = "[$choke[$i]]";
		}
	        printf "%-5d %-5d %3s %7.3f %-15s 0 %s %7.3f %s\n",
			$gaps[$i], $gap1[$i], $choke[$i],
			$rtt[$i], $ip[$i], $hosts[$i],
			$bw[$i], $bw_flag[$i];
	    }
	    print "$conf_line\n\n";
	    return;
	}

	open(OUT, ">tmp.in");
	for $i (0..$#gaps) {
	    # the last 2 items are simply for compatibility
	    print OUT "$rtt[$i] $gaps[$i] $ip[$i] 0 $hosts[$i]\n";
	}
	close OUT;

	# a dirty trick to flush the output, this is necessary on SUN
	system("$code_dir/get-choke tmp.in $pkt_size $pkt_num > tmp.main");
	open(IN2, "<tmp.main");
	    while (<IN2>) {
	    print "$_";
	}
	close IN2;
}
