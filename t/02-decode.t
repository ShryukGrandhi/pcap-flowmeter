use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use Craft;
use PcapFlow::Decode qw(decode ip_checksum addr_to_str str_to_addr);

sub ep { my $p = shift; ( addr_to_str( $p->{src} ), $p->{sport}, addr_to_str( $p->{dst} ), $p->{dport} ) }

# checksum: RFC 1071 example header from Wikipedia's IPv4 article
{
    my $h = pack 'H*', '450000730000400040110000c0a80001c0a800c7';
    is sprintf( '%04x', ip_checksum($h) ), 'b861', 'checksum of known header';
    substr( $h, 10, 2 ) = pack 'n', 0xb861;
    is ip_checksum($h), 0, 'valid header sums to zero';
    is ip_checksum("\x01"), 0xfeff, 'odd length padded';
}

# plain Ethernet / IPv4 / TCP
{
    my $p = decode( 1, eth( ipv4( '10.1.2.3', '10.9.8.7', 6, tcp( 1234, 80, 0x12 ) ) ), 1 );
    ok !$p->{err}, 'no error';
    is $p->{l3}, 4, 'ipv4';
    is $p->{proto}, 6, 'tcp';
    is_deeply [ ep($p) ], [ '10.1.2.3', 1234, '10.9.8.7', 80 ], 'endpoints';
    is $p->{tcp_flags}, 0x12, 'flags';
    is $p->{ip_len}, 40, 'ip length excludes ethernet padding';
    ok !$p->{csum_bad}, 'checksum verified ok';
    is $p->{vlan}, undef, 'untagged';
}

# corrupted IPv4 checksum is counted only when verification is on
{
    my $f = eth( ipv4( '1.1.1.1', '2.2.2.2', 17, udp( 5, 6 ) ) );
    substr( $f, 14 + 10, 1 ) ^= "\xff";
    ok decode( 1, $f, 1 )->{csum_bad}, 'bad checksum detected';
    ok !decode( 1, $f, 0 )->{csum_bad}, 'not checked when disabled';
}

# 802.1Q and QinQ
{
    my $p = decode( 1, eth( ipv4( '1.1.1.1', '2.2.2.2', 17, udp( 53, 999 ) ), 100 ) );
    is $p->{vlan}, 100, 'single tag';
    is $p->{sport}, 53, 'decoded past the tag';
    my $f = eth( ipv4( '1.1.1.1', '2.2.2.2', 17, udp( 53, 999 ) ), 300, 42 );
    substr( $f, 12, 2 ) = pack 'n', 0x88a8;
    $p = decode( 1, $f );
    is $p->{vlan}, 300, 'outer tag of QinQ';
    is $p->{dport}, 999, 'decoded past both tags';
}

# IPv6 with hop-by-hop + destination options before TCP
{
    my $ext = pack( 'C C', 60, 0 ) . ( "\0" x 6 ) . pack( 'C C', 6, 1 ) . ( "\0" x 14 );
    my $p = decode( 1, eth( ipv6( '2001:db8::1', '2001:db8::2', 0, $ext . tcp( 4000, 443, 0x02 ) ) ) );
    ok !$p->{err}, 'no error with ext headers';
    is $p->{l3}, 6, 'ipv6';
    is $p->{proto}, 6, 'walked ext header chain to tcp';
    is_deeply [ ep($p) ], [ '2001:db8::1', 4000, '2001:db8::2', 443 ], 'v6 endpoints';
    is $p->{ip_len}, 40 + 24 + 20, 'v6 length';
}

# IPv6 fragments: first has ports, later does not
{
    my $first = pack( 'C C n N', 17, 0, 0x0001, 99 ) . udp( 7, 8, 16 );
    my $p = decode( 101, ipv6( 'fe80::1', 'fe80::2', 44, $first ) );
    ok $p->{frag}, 'v6 first fragment flagged';
    is $p->{sport}, 7, 'first fragment has ports';
    my $later = pack( 'C C n N', 17, 0, ( 3 << 3 ), 99 ) . ( "\0" x 16 );
    $p = decode( 101, ipv6( 'fe80::1', 'fe80::2', 44, $later ) );
    ok $p->{frag}, 'v6 later fragment flagged';
    is $p->{proto}, 17, 'protocol known';
    is $p->{sport}, 0, 'no ports in later fragment';
}

# IPv4 fragments
{
    my $p = decode( 101, ipv4( '1.1.1.1', '2.2.2.2', 17, udp( 1, 2, 30 ), 0x2000 ) );
    ok $p->{frag}, 'MF set => fragment';
    is $p->{dport}, 2, 'first fragment has ports';
    $p = decode( 101, ipv4( '1.1.1.1', '2.2.2.2', 17, "\0" x 30, 0x0005 ) );
    ok $p->{frag}, 'offset => fragment';
    is $p->{sport}, 0, 'later fragment has no ports';
}

# ICMP: echo request/reply share the identifier; others use type/code
{
    my $req = decode( 101, ipv4( '1.1.1.1', '2.2.2.2', 1, icmp( 8, 0, 4242 ) ) );
    my $rep = decode( 101, ipv4( '2.2.2.2', '1.1.1.1', 1, icmp( 0, 0, 4242 ) ) );
    is_deeply [ $req->{sport}, $req->{dport} ], [ 4242, 4242 ], 'echo request id';
    is_deeply [ $rep->{sport}, $rep->{dport} ], [ 4242, 4242 ], 'echo reply id';
    my $un = decode( 101, ipv4( '2.2.2.2', '1.1.1.1', 1, icmp( 3, 3 ) ) );
    is_deeply [ $un->{sport}, $un->{dport} ], [ 3, 3 ], 'unreachable uses type/code';
    my $v6 = decode( 101, ipv6( '::1', '::2', 58, icmp( 128, 0, 7 ) ) );
    is $v6->{sport}, 7, 'icmpv6 echo id';
}

# Linux cooked captures and other link types
{
    my $ip = ipv4( '10.0.0.1', '10.0.0.2', 6, tcp( 22, 5555, 0x18, 10 ) );
    my $sll  = pack( 'n n n a8 n', 0, 1, 6, "\x02" x 6, 0x0800 ) . $ip;
    my $sll2 = pack( 'n n N n C C a8', 0x0800, 0, 3, 1, 0, 6, "\x02" x 6 ) . $ip;
    for my $c ( [ 'SLL', 113, $sll ], [ 'SLL2', 276, $sll2 ], [ 'RAW', 101, $ip ],
        [ 'IPV4', 228, $ip ], [ 'NULL le', 0, pack( 'V', 2 ) . $ip ], [ 'NULL be', 0, pack( 'N', 2 ) . $ip ] )
    {
        my $p = decode( $c->[1], $c->[2] );
        ok !$p->{err} && $p->{sport} == 22 && $p->{dport} == 5555, "$c->[0] decodes";
    }
    my $p = decode( 0, pack( 'V', 30 ) . ipv6( '::1', '::2', 17, udp( 1, 2 ) ) );
    is $p->{l3}, 6, 'NULL with BSD AF_INET6 (30)';
}

# non-IP and malformed input
{
    my $arp = ( "\xff" x 6 ) . ( "\x02" x 6 ) . pack( 'n', 0x0806 ) . ( "\0" x 28 );
    my $p = decode( 1, $arp );
    ok !$p->{err}, 'arp is not an error';
    is $p->{l3}, 0, 'arp is non-ip';
    is $p->{ethertype}, 0x0806, 'ethertype recorded';

    like decode( 1, "\0" x 10 )->{err}, qr/short ethernet/, 'runt frame';
    my $bad = eth( ipv4( '1.1.1.1', '2.2.2.2', 6, tcp( 1, 2, 2 ) ) );
    substr( $bad, 14, 1 ) = "\x43";    # IHL 3
    like decode( 1, $bad )->{err}, qr/header length/, 'IHL < 5';
    like decode( 101, "\x45" . "\0" x 10 )->{err}, qr/short ipv4/, 'short ipv4';
    like decode( 999, 'x' )->{err}, qr/unsupported linktype/, 'unknown linktype';

    # snaplen cut inside the TCP header
    my $cut = substr( eth( ipv4( '1.1.1.1', '2.2.2.2', 6, tcp( 1, 2, 2, 500 ) ) ), 0, 14 + 20 + 6 );
    $p = decode( 1, $cut );
    ok !$p->{err} && $p->{l4_trunc}, 'truncated l4 is flagged, packet still counted';
    is $p->{ip_len}, 540, 'ip length comes from the header, not the capture';
}

# address helpers
is addr_to_str( str_to_addr('2001:db8:0:0:0:0:0:1') ), '2001:db8::1', 'v6 roundtrip';
is str_to_addr('300.1.1.1'), undef, 'bad v4 rejected';

done_testing;
