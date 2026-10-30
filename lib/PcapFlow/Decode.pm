package PcapFlow::Decode;

# Link/network/transport decoder. Turns a captured frame into a flat hash:
#
#   l3       0 (not IP), 4 or 6
#   src,dst  packed addresses (4 or 16 bytes)
#   proto    IP protocol number (after IPv6 extension headers)
#   sport,dport  TCP/UDP ports; for ICMP echo both are the echo identifier,
#            otherwise ICMP type/code
#   tcp_flags, ip_len (bytes at L3), vlan (outer 802.1Q id), frag
#   err      set to a short reason when the frame could not be decoded
#
# Every field is always defined so filters can compare without warnings.

use strict;
use warnings;
use Exporter 'import';
use Socket qw(AF_INET AF_INET6 inet_ntop inet_pton);

our @EXPORT_OK = qw(decode ip_checksum addr_to_str str_to_addr
  supported_linktype linktype_name);

use constant {
    LINKTYPE_NULL       => 0,
    LINKTYPE_ETHERNET   => 1,
    LINKTYPE_RAW        => 101,
    LINKTYPE_LINUX_SLL  => 113,
    LINKTYPE_IPV4       => 228,
    LINKTYPE_IPV6       => 229,
    LINKTYPE_LINUX_SLL2 => 276,
};

my %LINKTYPE_NAME = (
    0   => 'NULL',
    1   => 'EN10MB',
    101 => 'RAW',
    113 => 'LINUX_SLL',
    228 => 'IPV4',
    229 => 'IPV6',
    276 => 'LINUX_SLL2',
);

sub supported_linktype { exists $LINKTYPE_NAME{ $_[0] } }
sub linktype_name      { $LINKTYPE_NAME{ $_[0] } // "linktype $_[0]" }

sub _new_packet {
    return {
        l3        => 0,
        src       => '',
        dst       => '',
        proto     => 0,
        sport     => 0,
        dport     => 0,
        tcp_flags => 0,
        ip_len    => 0,
        frag      => 0,
        vlan      => undef,
        err       => undef,
        len       => $_[0],
    };
}

sub decode {
    my ( $linktype, $data, $verify_csum ) = @_;
    my $len = length $data;
    my $p   = _new_packet($len);
    my ( $ethertype, $off );

    if ( $linktype == LINKTYPE_ETHERNET ) {
        return _err( $p, 'short ethernet' ) if $len < 14;
        $ethertype = unpack 'n', substr( $data, 12, 2 );
        $off       = 14;
        # 802.1Q, 802.1ad (QinQ) and the old 0x9100 tag; record the outer id
        while ( $ethertype == 0x8100 || $ethertype == 0x88a8 || $ethertype == 0x9100 ) {
            return _err( $p, 'short vlan tag' ) if $len < $off + 4;
            my ( $tci, $et ) = unpack 'n n', substr( $data, $off, 4 );
            $p->{vlan} //= $tci & 0x0fff;
            $ethertype = $et;
            $off += 4;
        }
    }
    elsif ( $linktype == LINKTYPE_LINUX_SLL ) {
        # pkttype(2) hatype(2) halen(2) addr(8) protocol(2)
        return _err( $p, 'short sll' ) if $len < 16;
        $ethertype = unpack 'n', substr( $data, 14, 2 );
        $off       = 16;
    }
    elsif ( $linktype == LINKTYPE_LINUX_SLL2 ) {
        # protocol(2) reserved(2) ifindex(4) hatype(2) pkttype(1) halen(1) addr(8)
        return _err( $p, 'short sll2' ) if $len < 20;
        $ethertype = unpack 'n', substr( $data, 0, 2 );
        $off       = 20;
    }
    elsif ( $linktype == LINKTYPE_RAW || $linktype == LINKTYPE_IPV4 || $linktype == LINKTYPE_IPV6 ) {
        return _err( $p, 'empty raw packet' ) if $len < 1;
        my $v = ord( $data ) >> 4;
        $ethertype = $v == 4 ? 0x0800 : $v == 6 ? 0x86dd : 0;
        $off       = 0;
    }
    elsif ( $linktype == LINKTYPE_NULL ) {
        # BSD loopback: 4-byte address family in the capturing host's order
        return _err( $p, 'short null header' ) if $len < 4;
        my $af = unpack 'V', $data;
        $af = unpack 'N', $data if $af > 0xffff;
        $ethertype = $af == 2 ? 0x0800
          : ( $af == 10 || $af == 24 || $af == 28 || $af == 30 ) ? 0x86dd
          :                                                       0;
        $off = 4;
    }
    else {
        return _err( $p, "unsupported linktype $linktype" );
    }

    return _ipv4( $p, $data, $off, $verify_csum ) if $ethertype == 0x0800;
    return _ipv6( $p, $data, $off )               if $ethertype == 0x86dd;
    $p->{ethertype} = $ethertype;
    return $p;
}

sub _err {
    my ( $p, $why ) = @_;
    $p->{err} = $why;
    return $p;
}

sub _ipv4 {
    my ( $p, $data, $off, $verify ) = @_;
    my $len = length $data;
    return _err( $p, 'short ipv4' ) if $len - $off < 20;

    my ( $vihl, $tot, $ff, $proto, $src, $dst ) =
      unpack 'C x n x2 n x C x2 a4 a4', substr( $data, $off, 20 );
    return _err( $p, 'bad ip version' ) if ( $vihl >> 4 ) != 4;
    my $ihl = ( $vihl & 0x0f ) * 4;
    return _err( $p, 'bad ipv4 header length' ) if $ihl < 20 || $len - $off < $ihl;
    return _err( $p, 'bad ipv4 total length' )  if $tot < $ihl;

    @$p{qw(l3 src dst proto ip_len)} = ( 4, $src, $dst, $proto, $tot );
    if ( $verify && ip_checksum( substr( $data, $off, $ihl ) ) != 0 ) {
        $p->{csum_bad} = 1;
    }

    my $frag_off = $ff & 0x1fff;
    $p->{frag} = 1 if $frag_off || ( $ff & 0x2000 );
    return $p if $frag_off;    # later fragments carry no transport header

    # Ethernet pads short frames; trust the IP total length, not the frame.
    my $end = $off + $tot;
    $end = $len if $end > $len;
    return _l4( $p, $data, $off + $ihl, $end, $proto, 4 );
}

my %V6_EXT = ( 0 => 1, 43 => 1, 60 => 1 );

sub _ipv6 {
    my ( $p, $data, $off ) = @_;
    my $len = length $data;
    return _err( $p, 'short ipv6' ) if $len - $off < 40;

    my ( $vtf, $plen, $nh, $src, $dst ) =
      unpack 'N n C x a16 a16', substr( $data, $off, 40 );
    return _err( $p, 'bad ip version' ) if ( $vtf >> 28 ) != 6;
    @$p{qw(l3 src dst ip_len)} = ( 6, $src, $dst, 40 + $plen );

    my $end = $off + 40 + $plen;
    $end = $len if $end > $len;
    my $o    = $off + 40;
    my $hops = 0;
    while (1) {
        if ( $V6_EXT{$nh} ) {    # hop-by-hop, routing, destination options
            return _err( $p, 'short ipv6 ext header' ) if $o + 2 > $end;
            my ( $next, $hlen ) = unpack 'C C', substr( $data, $o, 2 );
            $nh = $next;
            $o += ( $hlen + 1 ) * 8;
        }
        elsif ( $nh == 44 ) {    # fragment
            return _err( $p, 'short ipv6 fragment header' ) if $o + 8 > $end;
            my ( $next, $fo ) = unpack 'C x n', substr( $data, $o, 4 );
            $p->{frag} = 1;
            $nh = $next;
            $o += 8;
            if ( $fo >> 3 ) { $p->{proto} = $nh; return $p }
        }
        elsif ( $nh == 51 ) {    # authentication header
            return _err( $p, 'short ipv6 ah' ) if $o + 2 > $end;
            my ( $next, $hlen ) = unpack 'C C', substr( $data, $o, 2 );
            $nh = $next;
            $o += ( $hlen + 2 ) * 4;
        }
        else {
            last;
        }
        return _err( $p, 'too many ipv6 extension headers' ) if ++$hops > 8;
    }
    return _l4( $p, $data, $o, $end, $nh, 6 );
}

sub _l4 {
    my ( $p, $data, $o, $end, $proto, $ipver ) = @_;
    $p->{proto} = $proto;
    my $avail = $end - $o;

    if ( $proto == 6 ) {
        if ( $avail < 14 ) { $p->{l4_trunc} = 1; return $p }
        my ( $sp, $dp, $offflags ) = unpack 'n n x8 n', substr( $data, $o, 14 );
        @$p{qw(sport dport tcp_flags)} = ( $sp, $dp, $offflags & 0xff );
    }
    elsif ( $proto == 17 ) {
        if ( $avail < 4 ) { $p->{l4_trunc} = 1; return $p }
        @$p{qw(sport dport)} = unpack 'n n', substr( $data, $o, 4 );
    }
    elsif ( ( $proto == 1 && $ipver == 4 ) || ( $proto == 58 && $ipver == 6 ) ) {
        if ( $avail < 2 ) { $p->{l4_trunc} = 1; return $p }
        my ( $type, $code ) = unpack 'C C', substr( $data, $o, 2 );
        my $echo = $proto == 1 ? ( $type == 8 || $type == 0 )
                               : ( $type == 128 || $type == 129 );
        if ( $echo && $avail >= 6 ) {
            # request and reply share the identifier, so they form one flow
            my $id = unpack 'n', substr( $data, $o + 4, 2 );
            @$p{qw(sport dport)} = ( $id, $id );
        }
        else {
            @$p{qw(sport dport)} = ( $type, $code );
        }
        $p->{icmp_type} = $type;
    }
    return $p;
}

# RFC 1071 internet checksum. Returns 0 for a header whose checksum is valid.
sub ip_checksum {
    my $b = shift;
    $b .= "\0" if length($b) % 2;
    my $s = unpack '%32n*', $b;
    $s = ( $s & 0xffff ) + ( $s >> 16 ) while $s >> 16;
    return ~$s & 0xffff;
}

sub addr_to_str {
    my $a = shift;
    return join '.', unpack 'C4', $a if length $a == 4;
    return inet_ntop( AF_INET6, $a ) if length $a == 16;
    return '';
}

sub str_to_addr {
    my $s = shift;
    return inet_pton( AF_INET6, $s ) if $s =~ /:/;
    return unless $s =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    return if grep { $_ > 255 } $1, $2, $3, $4;
    return pack 'C4', $1, $2, $3, $4;
}

1;
