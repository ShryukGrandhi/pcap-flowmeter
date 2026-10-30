package Craft;

# Hand-built frames for decoder and flow-table tests.

use strict;
use warnings;
use Exporter 'import';
use PcapFlow::Decode qw(ip_checksum str_to_addr);

our @EXPORT = qw(tcp udp icmp ipv4 ipv6 eth pkt);

sub tcp {
    my ( $sp, $dp, $flags, $plen ) = @_;
    return pack( 'n n N N n n n n', $sp, $dp, 1, 0, ( 5 << 12 ) | $flags, 1024, 0, 0 )
      . ( "\0" x ( $plen // 0 ) );
}
sub udp { my ( $sp, $dp, $plen ) = @_; pack( 'n n n n', $sp, $dp, 8 + ( $plen // 0 ), 0 ) . ( "\0" x ( $plen // 0 ) ) }
sub icmp { my ( $type, $code, $id ) = @_; pack( 'C C n n n', $type, $code, 0, $id // 0, 1 ) . ( "\0" x 8 ) }

# ipv4(src, dst, proto, l4, frag_field)
sub ipv4 {
    my ( $s, $d, $proto, $l4, $ff ) = @_;
    my $h = pack 'C C n n n C C n a4 a4', 0x45, 0, 20 + length $l4, 7, $ff // 0, 64,
      $proto, 0, str_to_addr($s), str_to_addr($d);
    substr( $h, 10, 2 ) = pack 'n', ip_checksum($h);
    return $h . $l4;
}

# ipv6(src, dst, next_header, payload) - payload may include ext headers
sub ipv6 {
    my ( $s, $d, $nh, $pl ) = @_;
    return pack( 'N n C C a16 a16', 6 << 28, length $pl, $nh, 64, str_to_addr($s), str_to_addr($d) ) . $pl;
}

sub eth {
    my ( $ip, @vlans ) = @_;
    my $et = ( ord($ip) >> 4 ) == 6 ? 0x86dd : 0x0800;
    my $f = ( "\x02" x 6 ) . ( "\x04" x 6 );
    $f .= pack 'n n', 0x8100, $_ for @vlans;
    $f .= pack( 'n', $et ) . $ip;
    $f .= "\0" x ( 60 - length $f ) if length $f < 60;
    return $f;
}

# decoded packet for flow-table tests
sub pkt {
    my ( $proto, $s, $sp, $d, $dp, %o ) = @_;
    my $sa = str_to_addr($s);
    return {
        l3 => length $sa == 4 ? 4 : 6, proto => $proto, src => $sa, dst => str_to_addr($d),
        sport => $sp, dport => $dp, tcp_flags => $o{flags} // 0, ip_len => $o{len} // 40,
        vlan => $o{vlan}, frag => 0,
    };
}

1;
