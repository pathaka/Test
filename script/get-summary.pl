#!/usr/bin/perl

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

open(proc_in, "<$ARGV[0]");

# set the conf & d_rate threshold
$req_conf = 0.1;
$req_d_rate = 0.5;

$index = 0;
$group_i = 0;

while (<proc_in>) {
	chomp;
	@F = split;
	shift @F if ($F[0] eq "");

	# the head line
	if ($F[0] eq "info") {
		$probing_dst = $F[2];
		$info_line[$group_i] = $_;
		next;
	}

	# the confidence line
	if ($F[0] eq "conf") {
		$total ++;
		for $i (2..$#F) {
		    $conf_data[$group_i][$i-2] = $F[$i];
		}
		$conf_cnt[$group_i] = @F - 2;
		$conf_line[$group_i] = $_;

		# the route doesn't need to be exactly the same
		$routes[$group_i] = $cur_route;
		foreach $tmp_id (keys %route) {
		    if ($tmp_id =~ /$cur_route/) {
		        $route{$cur_route} ++;
			$cur_route = "";
			last;
		    }
		}
		if ($cur_route ne "") {
		    $route{$cur_route} ++;
		}

		$index = 0;
		$cur_route = "";
		$group_i ++;
		next;
	}
	next if (@F < 5 || $F[0] eq "rtt");

	# the data line
	$real_gap[$group_i][$index] = $F[0];
	$gap[$group_i][$index] = $F[1];
	$name[$group_i][$index] = $F[$#F];
	$as[$group_i][$index] = $F[$#F-3];
	$rtt[$group_i][$index] = $F[$#F-5];
	$point[$group_i][$index] = 0;
	$size[$group_i] = $index;

	$name2ip{$F[$#F]} = $F[$#F-4];
	$cur_route .= "$F[$#F-4] ";
	
	# the choke point line
	if (@F == 9) {
		$i = substr($F[2], 1, 1) - 1;
		$loc{$F[8]} ++;
		$host[$group_i][$i] = $F[8];
		$host_index[$group_i][$i] = $index;

		$point[$group_i][$index] = 1;
		$flag[$group_i][$index] = $F[2];
	}

	$index ++;
}
close(proc_in);

&sanity_route;
&detect;
&get_change;
&dump;

###########################################################
# find the dominant route, and filter the data
sub sanity_route {
	local($max_route, $max_num, $cur_route);
	local(@sd, @valid);

	# find the dominant route
	$max_num = 0;
	foreach $cur_route (keys %route) {
	    if ($route{$cur_route} > $max_num) {
	    	$max_route = $cur_route;
		$max_num = $route{$cur_route};
	    }
	}

	# clean the other non-donimant route's data
	for $i (0..($group_i-1)) {
	    if ($max_route eq $routes[$i]) {
	        $valid[@valid] = $i;
	    }
	}

	# give up if the dominant route is less than 5
	exit if (@valid < 5);

	for $i (0..$#valid) {
	    @{$gap[$i]} = @{$gap[$valid[$i]]};
	    @{$real_gap[$i]} = @{$real_gap[$valid[$i]]};
	    @{$name[$i]} = @{$name[$valid[$i]]};
	    @{$as[$i]} = @{$as[$valid[$i]]};
	    @{$rtt[$i]} = @{$rtt[$valid[$i]]};
	    @{$point[$i]} = @{$point[$valid[$i]]};
	    $size[$i] = $size[$valid[$i]];
	    @{$conf_data[$i]} = @{$conf_data[$valid[$i]]};

	    @{$host[$i]} = @{$host[$valid[$i]]};
	    @{$host_index[$i]} = @{$host_index[$valid[$i]]};
	    @{$point[$i]} = @{$point[$valid[$i]]};
	    @{$flag[$i]} = @{$flag[$valid[$i]]};

	    # set the conf
	    for $j (0..($conf_cnt[$i]-1)) {
		if ($conf_data[$i][$j] > $req_conf) {
		    $conf{$host[$i][$j]} ++;
		} else {
		    $point[$i][$host_index[$i][$j]] = 0;
		}
	    }
	}
	$group_i = $#valid + 1;
	$total = $group_i;
}

###########################################################
# find out those routers with d_rate > 0.5
sub detect {
    local(@sd, $i, $id);

    @sd = reverse sort {$a <=> $b} (values %conf);

    if (!$total) {
        # no probing results
    	return;

    } elsif (@sd == 0 || $sd[0] / $total < $req_d_rate) {
        # no big confidence points
    	return;

    } else {
	for $i (0..$#sd) {
	    # if $sd[$i] equals $sd[$i-1], the corresponding
	    # hop has been picked out from the loop, so no need to
	    # check again
	    next if ($i>0 && $sd[$i] == $sd[$i-1]);
	    last if ($sd[$i] / $total < $req_d_rate);

	    for $id (keys %conf) {
		if ($conf{$id} == $sd[$i]) {
		    $detected{$id} = $sd[$i] / $total;
		}
	    }
	}
    }
}

###########################################################
# compute the final output: inc, dec, as_path, avg_gap
sub get_change {
    local($i, $j, $id, @sd, %tmp_pos);	

    for $i (0..($group_i-1)) {
        for $j (0..$size[$i]) {
	    $id = $name[$i][$j]; 
	    next if (!defined $detected{$id});
	    next if (!$point[$i][$j]); 

	    if ($j > 0) {
	        $chg{$id} ++;
		$avg_gap{$id} += $gap[$i][$j];
		$avg_pos{$id} += $j;
	    }
	}
    }

    # compute the avg_gap
    for $id (keys %avg_gap) {
        $avg_gap{$id} /= ($detected{$id} * $total);
        $avg_pos{$id} /= ($detected{$id} * $total);
    }

    @sd = reverse sort {$a <=> $b} (values %avg_pos);
    %tmp_pos = %avg_pos;
    
    for $i (0..$#sd) {
    	for $id (keys %tmp_pos) {
	    if ($tmp_pos{$id} == $sd[$i]) {
	    	$sorted_host[$i] = $id;
		delete $tmp_pos{$id};
		last;
	    }
	}
    }
}

###########################################################
sub dump {
 	local($i, $j, $id);

	for $i (0..$#sorted_host) {
	     	$id = $sorted_host[$i];
		printf "sum: %.2f %02d %02d %6d %2d %s\n", 
			$detected{$id}, $total, $chg{$id},
			$avg_gap{$id}, int($avg_pos{$id}),
			$name2ip{$id}; 
	}
	print "\n";
}
