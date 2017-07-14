#!/usr/bin/perl

use Socket;
use XML::LibXML;
use Getopt::Std;

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
		foreach my $rasfilter ($prop->getElementsByTagName("msRASFilter")) {
		    my $binhex = $rasfilter->textContent;
		    $out->{"$connectionName"} = {};
		    $out->{"$connectionName"}->{'name'} = $connectionName;
		    $out->{"$connectionName"}->{'list'} = &decode_acl($binhex);
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
	print "- '$name'\n";
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
    printf("%s,%s,%s,%s,%s,%s,%s,%s\n", "name", "src-ip", "src-netmask", "dst-ip", "dst-netmask", "protocol", "protocol-ext", "src-port", "dst-port");
    foreach my $name (sort keys %{$ret}) {
	foreach my $cur (@{$ret->{"$name"}->{'list'}}) {
	    printf(
		"\"%s\",%s,%s,%s,%s,%s,%s,%d,%d\n",
		$name,
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
	printf("%30s %15s %15s %15s %15s %10s %4s %10s %10s\n", "name", "src-ip", "src-netmask", "dst-ip", "dst-netmask", "protocol", "protocol-ext", "src-port", "dst-port");
	foreach my $cur (@{$ret->{"$name"}->{'list'}}) {
	    printf(
		"%30s %15s %15s %15s %15s %10s %4s %10d %10d\n",
		$name,
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
