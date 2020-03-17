#!/usr/bin/perl

use strict;
use warnings;
use Socket;
use XML::LibXML;
use Getopt::Std;

our ($opt_f,$opt_o);

sub hex2ip()
{
    my $in = shift || "";
    return inet_ntoa(pack("N", hex("$in")));
}

sub hex2proto()
{
    my $in = shift || "";
    my $proto = hex("$in");
    my $proto_h = $proto >> 24;
    if ($proto_h == 6) {
	return "TCP";
    } elsif ($proto_h == 17) {
	return "UDP";
    } elsif ($proto_h == 1) {
	return "ICMP";
    } elsif ($proto_h == 0) {
	return "ANY";
    }

    return $proto_h;
}

sub hex2port()
{
    my $proto = shift || "";
    my $in = shift || "";
    my $port = hex("$in");
    if ($proto eq 'ICMP') {
	$port = $port >> 8;
	if ($port == 255) {
	    return -1;
	}
    }
    return $port;
}

sub hex2proto_ext()
{
    my $in = shift || "";
    my $proto = hex("$in");
    my $proto_h = $proto >> 24;
    if ($proto_h == 81) {
	return "est";
    }
    if ($proto_h == 17) {
	return "-";
    }
    return "-";
}

sub decode_acl()
{
    my $data = shift || "";
    my $acllist = [];

    for (my $i=32+56; $i<length($data); $i+=56) {
        my $cur = substr($data, $i, 56);
        
        my $src_ip = &hex2ip(substr($cur, 0, 8));
        my $src_netmask = &hex2ip(substr($cur, 8, 8));
        my $dst_ip = &hex2ip(substr($cur, 16, 8));
        my $dst_netmask = &hex2ip(substr($cur, 24, 8));
        my $proto = &hex2proto(substr($cur, 32, 8));
        my $proto_ext = &hex2proto_ext(substr($cur, 40, 8));
        my $src_port = &hex2port($proto, substr($cur, 48, 4));
        my $dst_port = &hex2port($proto, substr($cur, 52, 4));

	push(@{$acllist}, {
	    'src_ip'		=> $src_ip,
	    'src_netmask'	=> $src_netmask,
	    'dst_ip'		=> $dst_ip,
	    'dst_netmask'	=> $dst_netmask,
	    'proto'		=> $proto,
	    'proto_ext'		=> $proto_ext,
	    'src_port'		=> $src_port,
	    'dst_port'		=> $dst_port
	});
    }
    return $acllist;
}

sub nofilter_acl()
{
    my $acllist = [];
    my $src_ip = "0.0.0.0";
    my $src_netmask = "0.0.0.0";
    my $dst_ip = "0.0.0.0";
    my $dst_netmask = "0.0.0.0";
    my $proto = "ANY";
    my $proto_ext = "-";
    my $src_port = -1;
    my $dst_port = -1;

    push(@{$acllist}, {
        'src_ip'		=> $src_ip,
        'src_netmask'	=> $src_netmask,
        'dst_ip'		=> $dst_ip,
        'dst_netmask'	=> $dst_netmask,
        'proto'		=> $proto,
        'proto_ext'		=> $proto_ext,
        'src_port'		=> $src_port,
        'dst_port'		=> $dst_port
    });
    
    return $acllist;
}

sub do_error()
{
    my $msg = shift || "unknown";
    printf STDERR ("%s ERROR > %s\n", scalar localtime, $msg);
    exit(1);
}

sub getUsage()
{
    return "Usage: inputcommand|$0 or $0 -f <input xmlfile> -o <text|csv|grep>";
}

sub parse_xml()
{
    my $xmlString = shift || "";
    my $out = {};
    my $pp = XML::LibXML->new();
    my $doc = $pp->parse_string($xmlString);
    undef($xmlString);
    my @radiusprofiles = $doc->getElementsByTagName('RadiusProfiles');
    foreach my $radiusprofile (@radiusprofiles) {
	my @children = $radiusprofile->getElementsByTagName('Children');
	foreach my $child (@children) {
	    foreach my $prop ($child->getElementsByTagName('Properties')) {
		my $parent = $prop->getParentNode;
		my $connectionName = $parent->getAttribute("name");
		my $filter_found = 0;

		foreach my $rasfilter ($prop->getElementsByTagName("msRASFilter")) {
		    $filter_found = 1;
		    my $binhex = $rasfilter->textContent;
		    $out->{"$connectionName"} = {};
		    $out->{"$connectionName"}->{'name'} = $connectionName;
		    $out->{"$connectionName"}->{'list'} = &decode_acl($binhex);
		    $out->{"$connectionName"}->{'policy'} = [];
		}
		if (!$filter_found) {
		    $out->{"$connectionName"} = {};
		    $out->{"$connectionName"}->{'name'} = $connectionName;
		    $out->{"$connectionName"}->{'list'} = &nofilter_acl();
		    $out->{"$connectionName"}->{'policy'} = [];
		}
	
	    }
	}
    }
    my @networkpolicies = $doc->getElementsByTagName('NetworkPolicy');
    foreach my $networkpolicy (@networkpolicies) {
	my @children = $networkpolicy->getElementsByTagName('Children');
	foreach my $child (@children) {
	    foreach my $prop ($child->getElementsByTagName('Properties')) {
		my $parent = $prop->getParentNode;
		my $connectionName = $parent->getAttribute("name");
		my $filter_found = 0;
		foreach my $msnp ($prop->getElementsByTagName("msNPConstraint")) {
		    if (!defined($out->{"$connectionName"})) {
			next;
		    }
		    push(@{$out->{"$connectionName"}->{'policy'}}, $msnp->textContent);
		}
	    }
	}
    }

    return $out;
}

sub print_out_text()
{
    my $ret = shift || {};
    foreach my $name (sort keys %{$ret}) {
	my $policy_str = 0;
	if (scalar @{$ret->{"$name"}->{'policy'}}) {
	    $policy_str = join(" && ", @{$ret->{"$name"}->{'policy'}});
	}
	if ($policy_str) {
	    print "- '$name' ($policy_str)\n";
	} else {
	    print "- '$name'\n";
	}
	foreach my $cur (@{$ret->{"$name"}->{'policy'}}) {
	    print "$cur\n";
	}

	printf("%15s %15s %15s %15s %10s %4s %10s %10s\n", "src-ip", "src-netmask", "dst-ip", "dst-netmask", "protocol", "protocol-ext", "src-port", "dst-port");
	foreach my $cur (@{$ret->{"$name"}->{'list'}}) {
	    printf(
		"%15s %15s %15s %15s %10s %4s %10d %10d\n",
		$cur->{'src_ip'}, $cur->{'src_netmask'},
		$cur->{'dst_ip'}, $cur->{'dst_netmask'},
		$cur->{'proto'},
		$cur->{'proto_ext'},
		$cur->{'src_port'},
		$cur->{'dst_port'}
	    );
	}
	print "\n";
    }
}

sub print_out_csv()
{
    my $ret = shift || {};
    printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", "name", "policy", "src-ip", "src-netmask", "dst-ip", "dst-netmask", "protocol", "protocol-ext", "src-port", "dst-port");
    foreach my $name (sort keys %{$ret}) {
    	my $policy_str = 0;
	if (scalar @{$ret->{"$name"}->{'policy'}}) {
	    $policy_str = join(" && ", @{$ret->{"$name"}->{'policy'}});
	    $policy_str =~ s/"/\\"/g;
	}

	foreach my $cur (@{$ret->{"$name"}->{'list'}}) {
	    printf(
		"\"%s\",\"%s\",%s,%s,%s,%s,%s,%s,%d,%d\n",
		$name,
		$policy_str,
		$cur->{'src_ip'}, $cur->{'src_netmask'},
		$cur->{'dst_ip'}, $cur->{'dst_netmask'},
		$cur->{'proto'},
		$cur->{'proto_ext'},
		$cur->{'src_port'},
		$cur->{'dst_port'}
	    );
	}
    }
}

sub print_out_grep()
{
    my $ret = shift || {};
    foreach my $name (sort keys %{$ret}) {
    	my $policy_str = "";
	if (scalar @{$ret->{"$name"}->{'policy'}}) {
	    $policy_str = join(" && ", @{$ret->{"$name"}->{'policy'}});
	}

	printf("%30s %15s %15s %15s %15s %10s %12s %10s %10s %s\n", "name", "src-ip", "src-netmask", "dst-ip", "dst-netmask", "protocol", "protocol-ext", "src-port", "dst-port", "policy");
	foreach my $cur (@{$ret->{"$name"}->{'list'}}) {
	    printf(
		"%30s %15s %15s %15s %15s %10s %12s %10d %10d %s\n",
		$name,
		$cur->{'src_ip'}, $cur->{'src_netmask'},
		$cur->{'dst_ip'}, $cur->{'dst_netmask'},
		$cur->{'proto'},
		$cur->{'proto_ext'},
		$cur->{'src_port'},
		$cur->{'dst_port'},
		$policy_str
	    );
	}
	print "\n";
    }
}

sub main()
{
    getopt("o:f:");
    my $xmlString = "";
    if (defined($opt_f)) {
	local *F;
	my $xmlFile = $opt_f;
	open(F, $xmlFile) || &do_error("File open error($xmlFile): $!");
	read(F, $xmlString, -s $xmlFile);
	close(F);
    } else {
	if (-l "/proc/self/fd/0") {
	    my $stdinFile = readlink("/proc/self/fd/0");
	    if ($stdinFile !~ /pipe/) {
		&do_error(&getUsage());
	    }
	}
	while (<STDIN>) {
	    $xmlString .= $_;
	}
    }
    my $ret = &parse_xml($xmlString);
    if (defined($opt_o)) {
	if ($opt_o eq 'text') {
	    &print_out_text($ret);
	} elsif ($opt_o eq 'csv') {
	    &print_out_csv($ret);
	} elsif ($opt_o eq 'grep') {
	    &print_out_grep($ret);
	}
    } else {
	&print_out_text($ret);
    }
}


&main();
