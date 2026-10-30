package PcapFlow::Gen;

# Deterministic synthetic traffic generator with ground truth.
#
# Produces complete conversations (TCP with handshake and FIN teardown, UDP
# request/response, ICMP echo), interleaved in time, over IPv4 or IPv6,
# optionally 802.1Q-tagged, framed for Ethernet, Linux SLL/SLL2 or raw IP.
# For every conversation it also returns the expected flow record, which
# the tests and the benchmark use to score the flow meter's accuracy.
#
# Uses its own xorshift32 PRNG so a seed gives identical bytes on every
# platform and perl version.

use strict;
use warnings;
use Carp qw(croak);
use PcapFlow::Decode qw(ip_checksum addr_to_str);
use PcapFlow::Writer;

sub new {
    my ( $class, %o ) = @_;
    my $seed = ( $o{seed} // 1 ) & 0xffffffff;
    return bless { s => $seed || 0x9e3779b9 }, $class;
}

sub _rand {
    my $self = shift;
    my $x    = $self->{s};
    $x ^= ( $x << 13 ) & 0xffffffff;
    $x ^= $x >> 17;
    $x ^= ( $x << 5 ) & 0xffffffff;
    return $self->{s} = $x;
}

sub rint { $_[0]->_rand % $_[1] }

my @TCP_PORTS = ( 80, 443, 443, 443, 8080, 22 );
my @UDP_PORTS = ( 53, 53, 123, 5353 );

# %o: flows, start_us, gap_us, v6_pct, vlan_pct, linktype, tcp_pct, udp_pct
sub generate {
    my ( $self, %o ) = @_;
    my $nflows   = $o{flows}    // 1000;
    my $start    = $o{start_us} // 1_700_000_000_000_000;
    my $gap      = $o{gap_us}   // 500;
    my $v6_pct   = $o{v6_pct}   // 20;
    my $vlan_pct = $o{vlan_pct} // 10;
    my $tcp_pct  = $o{tcp_pct}  // 60;
    my $udp_pct  = $o{udp_pct}  // 30;
    my $lt       = $o{linktype} // 1;
    croak "Gen: unsupported linktype $lt" unless $lt =~ /^(1|101|113|276)$/;

    my ( @pk, @truth );
    my $seq = 0;
    for my $i ( 0 .. $nflows - 1 ) {
        my $kind = $self->rint(100);
        my $proto = $kind < $tcp_pct ? 6 : $kind < $tcp_pct + $udp_pct ? 17 : 0;
        my $v6   = $self->rint(100) < $v6_pct;
        $proto = $v6 ? 58 : 1 if $proto == 0;
        my $vlan = ( $lt == 1 && $self->rint(100) < $vlan_pct ) ? 1 + $self->rint(4094) : undef;

        my ( $cli, $srv );
        if ($v6) {
            $cli = pack 'n8', 0xfd00, 0, 0, 0, 0, 0, ( $i >> 16 ) & 0xffff, $i & 0xffff;
            $srv = pack 'n8', 0xfd00, 0, 0, 1, 0, 0, 0, 1 + $self->rint(50);
        }
        else {
            $cli = pack 'C4', 10, ( $i >> 16 ) & 255, ( $i >> 8 ) & 255, $i & 255;
            $srv = pack 'C4', 192, 168, 0, 1 + $self->rint(50);
        }

        # conversation script: [from_client, tcp_flags, payload_len]
        my ( @script, $cport, $sport );
        if ( $proto == 6 ) {
            $cport = 32768 + $self->rint(28000);
            $sport = $TCP_PORTS[ $self->rint( scalar @TCP_PORTS ) ];
            push @script, [ 1, 0x02, 0 ], [ 0, 0x12, 0 ], [ 1, 0x10, 0 ];
            for ( 1 .. 1 + $self->rint(8) ) {
                push @script, [ 1, 0x18, 50 + $self->rint(400) ],
                  [ 0, 0x18, 100 + $self->rint(1300) ];
            }
            push @script, [ 1, 0x11, 0 ], [ 0, 0x11, 0 ], [ 1, 0x10, 0 ];
        }
        elsif ( $proto == 17 ) {
            $cport = 32768 + $self->rint(28000);
            $sport = $UDP_PORTS[ $self->rint( scalar @UDP_PORTS ) ];
            push @script, [ 1, 0, 30 + $self->rint(60) ], [ 0, 0, 60 + $self->rint(400) ]
              for 1 .. 1 + $self->rint(3);
        }
        else {
            $cport = $sport = $self->rint(65536);    # echo identifier
            push @script, [ 1, 0, 56 ], [ 0, 0, 56 ] for 1 .. 1 + $self->rint(4);
        }

        my $t = $start + $i * $gap + $self->rint($gap);
        my %tr = (
            proto => $proto, src => addr_to_str($cli), sport => $cport,
            dst   => addr_to_str($srv), dport => $sport, vlan => $vlan,
            pkts_fwd => 0, pkts_rev => 0, bytes_fwd => 0, bytes_rev => 0,
            first_us => $t,
        );
        my ( $cseq, $sseq ) = ( $self->_rand, $self->_rand );
        my $n = 0;
        for my $step (@script) {
            my ( $fromc, $flags, $plen ) = @$step;
            my ( $s, $d, $sp, $dp ) = $fromc ? ( $cli, $srv, $cport, $sport ) : ( $srv, $cli, $sport, $cport );
            my $l4;
            if ( $proto == 6 ) {
                my ( $sq, $ak ) = $fromc ? ( $cseq, $sseq ) : ( $sseq, $cseq );
                $l4 = pack( 'n n N N n n n n', $sp, $dp, $sq, ( $flags & 0x10 ) ? $ak : 0,
                    ( 5 << 12 ) | $flags, 65535, 0, 0 ) . ( "\0" x $plen );
                my $adv = $plen + ( ( $flags & 0x03 ) ? 1 : 0 );
                if ($fromc) { $cseq = ( $cseq + $adv ) & 0xffffffff }
                else        { $sseq = ( $sseq + $adv ) & 0xffffffff }
            }
            elsif ( $proto == 17 ) {
                $l4 = pack( 'n n n n', $sp, $dp, 8 + $plen, 0 ) . ( "\0" x $plen );
            }
            else {
                my $type = $proto == 1 ? ( $fromc ? 8 : 0 ) : ( $fromc ? 128 : 129 );
                $l4 = pack( 'C C n n n', $type, 0, 0, $cport, int( $n / 2 ) ) . ( "\0" x $plen );
            }
            my $ip    = $v6 ? _ipv6( $s, $d, $proto, $l4 ) : _ipv4( $s, $d, $proto, $l4, $i + $n );
            my $frame = _frame( $lt, $ip, $v6, $vlan, $fromc );
            push @pk, [ $t, $seq++, $frame ];
            if ($fromc) { $tr{pkts_fwd}++; $tr{bytes_fwd} += length $ip }
            else        { $tr{pkts_rev}++; $tr{bytes_rev} += length $ip }
            $tr{last_us} = $t;
            $n++;
            $t += 100 + $self->rint(20000) if $n < @script;
        }
        push @truth, \%tr;
    }
    @pk = sort { $a->[0] <=> $b->[0] || $a->[1] <=> $b->[1] } @pk;
    return { packets => \@pk, truth => \@truth, linktype => $lt };
}

sub _ipv4 {
    my ( $s, $d, $proto, $l4, $id ) = @_;
    my $h = pack 'C C n n n C C n a4 a4', 0x45, 0, 20 + length $l4, $id & 0xffff,
      0x4000, 64, $proto, 0, $s, $d;
    substr( $h, 10, 2 ) = pack 'n', ip_checksum($h);
    return $h . $l4;
}

sub _ipv6 {
    my ( $s, $d, $proto, $l4 ) = @_;
    return pack( 'N n C C a16 a16', 6 << 28, length $l4, $proto, 64, $s, $d ) . $l4;
}

my $MAC_C = pack 'H12', '020000000001';
my $MAC_S = pack 'H12', '020000000002';

sub _frame {
    my ( $lt, $ip, $v6, $vlan, $fromc ) = @_;
    my $et = $v6 ? 0x86dd : 0x0800;
    return $ip if $lt == 101;
    my ( $smac, $dmac ) = $fromc ? ( $MAC_C, $MAC_S ) : ( $MAC_S, $MAC_C );
    if ( $lt == 113 ) {
        return pack( 'n n n a8 n', $fromc ? 4 : 0, 1, 6, $smac, $et ) . $ip;
    }
    if ( $lt == 276 ) {
        return pack( 'n n N n C C a8', $et, 0, 2, 1, $fromc ? 4 : 0, 6, $smac ) . $ip;
    }
    my $f = $dmac . $smac
      . ( defined $vlan ? pack( 'n n', 0x8100, $vlan ) : '' )
      . pack( 'n', $et ) . $ip;
    $f .= "\0" x ( 60 - length $f ) if length $f < 60;    # Ethernet minimum frame
    return $f;
}

# Write a generate() result (or a slice of its packets) as a pcap file.
sub write_pcap {
    my ( $class, $path, $gen, %o ) = @_;
    my $w = PcapFlow::Writer->new( path => $path, linktype => $gen->{linktype}, %o );
    my $pk = $o{packets} || $gen->{packets};
    for my $p (@$pk) {
        my $us = $p->[0];
        $w->write_packet( int( $us / 1_000_000 ), $us % 1_000_000, $p->[2] );
    }
    $w->close;
    return scalar @$pk;
}

1;
