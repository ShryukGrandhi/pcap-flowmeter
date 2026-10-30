use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use Craft;
use PcapFlow::FlowTable;

sub table {
    my @out;
    my $t = PcapFlow::FlowTable->new( idle_timeout => 10, close_timeout => 2, on_export => sub { push @out, $_[0] }, @_ );
    return ( $t, \@out );
}

use constant { FIN => 1, SYN => 2, RST => 4, PSH => 8, ACK => 16 };

# A full TCP conversation: both directions merge, initiator is the SYN sender
{
    my ( $t, $out ) = table();
    my @c = ( 6, '10.0.0.1', 40000, '10.0.0.2', 80 );
    my @s = ( 6, '10.0.0.2', 80, '10.0.0.1', 40000 );
    $t->add( pkt( @c, flags => SYN, len => 60 ), 100.000 );
    $t->add( pkt( @s, flags => SYN | ACK, len => 60 ), 100.010 );
    $t->add( pkt( @c, flags => ACK, len => 52 ), 100.025 );
    $t->add( pkt( @c, flags => PSH | ACK, len => 500 ), 100.030 );
    $t->add( pkt( @s, flags => PSH | ACK, len => 1500 ), 100.050 );
    $t->add( pkt( @c, flags => FIN | ACK ), 100.060 );
    $t->add( pkt( @s, flags => FIN | ACK ), 100.070 );
    is $t->active, 1, 'one flow for both directions';
    $t->add( pkt( @c, flags => ACK ), 100.080 );    # last ACK, after close
    is scalar @$out, 0, 'not exported yet (close linger)';
    $t->expire(102.079);
    is scalar @$out, 0, 'still lingering just before close timeout';
    $t->expire(102.080);
    is scalar @$out, 1, 'exported at close timeout';
    my $f = $out->[0];
    is_deeply [ @$f{qw(src sport dst dport)} ], [ '10.0.0.1', 40000, '10.0.0.2', 80 ], 'oriented initiator->responder';
    is_deeply [ @$f{qw(pkts_fwd pkts_rev bytes_fwd bytes_rev)} ], [ 5, 3, 60 + 52 + 500 + 40 + 40, 60 + 1500 + 40 ], 'counters';
    is $f->{tcp_flags}, 'FSPA', 'flag union';
    is $f->{end}, 'close', 'end reason';
    cmp_ok abs( $f->{rtt} - 0.025 ), '<', 1e-9, 'handshake rtt = SYN to final ACK';
    is $f->{last} - $f->{first}, 100.080 - 100.000, 'duration';
}

# capture starts mid-handshake: SYN/ACK first => receiver is the initiator
{
    my ( $t, $out ) = table();
    $t->add( pkt( 6, '10.0.0.2', 443, '10.0.0.1', 5000, flags => SYN | ACK ), 1 );
    $t->add( pkt( 6, '10.0.0.1', 5000, '10.0.0.2', 443, flags => ACK ), 1.1 );
    $t->flush;
    is_deeply [ @{ $out->[0] }{qw(src sport dst dport pkts_fwd pkts_rev)} ],
      [ '10.0.0.1', 5000, '10.0.0.2', 443, 1, 1 ], 'SYN/ACK flips orientation';
    is $out->[0]{rtt}, undef, 'no rtt without the SYN';
}

# idle timeout splits a flow, exactly at the boundary
{
    my ( $t, $out ) = table();
    my @u = ( 17, '192.168.1.1', 5353, '224.0.0.251', 5353 );
    $t->add( pkt(@u), 0 );
    $t->add( pkt(@u), 4 );
    $t->add( pkt(@u), 14 );    # exactly 10 later => new flow
    $t->flush;
    is scalar @$out, 2, 'idle gap of exactly idle_timeout splits';
    is $out->[0]{pkts_fwd}, 2, 'first part';
    is $out->[0]{end}, 'idle', 'first part ended idle';
    is $out->[1]{end}, 'eof', 'second part ended at eof';
}

# lazy expiry queue: an active flow is re-queued, an idle one is reaped
{
    my ( $t, $out ) = table();
    my @a = ( 17, '1.1.1.1', 1, '2.2.2.2', 2 );
    my @b = ( 17, '3.3.3.3', 3, '4.4.4.4', 4 );
    $t->add( pkt(@a), 0 );
    $t->add( pkt(@b), 0 );
    $t->add( pkt(@a), 8 );
    $t->expire(10);
    is_deeply [ map { $_->{src} } @$out ], ['3.3.3.3'], 'only the idle flow expired';
    $t->expire(17.9);
    is scalar @$out, 1, 'requeued flow not expired early';
    $t->expire(18);
    is scalar @$out, 2, 'requeued flow expires at last+timeout';
    is $t->active, 0, 'table empty';
}

# packets drive expiry: no explicit expire() needed
{
    my ( $t, $out ) = table();
    $t->add( pkt( 17, "10.0.0.$_", 1000, '10.1.1.1', 53 ), $_ * 0.01 ) for 1 .. 50;
    is $t->active, 50, '50 active flows';
    $t->add( pkt( 17, '10.9.9.9', 1, '10.1.1.1', 53 ), 30 );
    is scalar @$out, 50, 'stale flows reaped when time advances';
    is $t->peak, 50, 'peak tracked';
}

# RST closes; a new SYN on a closed flow starts a new one (port reuse)
{
    my ( $t, $out ) = table();
    my @c = ( 6, '10.0.0.1', 1111, '10.0.0.2', 22 );
    my @s = ( 6, '10.0.0.2', 22, '10.0.0.1', 1111 );
    $t->add( pkt( @c, flags => SYN ), 0 );
    $t->add( pkt( @s, flags => RST | ACK ), 0.001 );
    $t->add( pkt( @c, flags => SYN ), 0.5 );
    is scalar @$out, 1, 'reused port exported the old flow';
    is $out->[0]{end}, 'reuse', 'end=reuse';
    is $out->[0]{tcp_flags}, 'SRA', 'flags of the refused connection';
    $t->flush;
    is scalar @$out, 2, 'new flow present';
    is $out->[1]{pkts_fwd}, 1, 'new flow has only the new SYN';
}

# a flow that only closed in one direction is not closed
{
    my ( $t, $out ) = table();
    $t->add( pkt( 6, '1.1.1.1', 1, '2.2.2.2', 2, flags => FIN | ACK ), 0 );
    $t->expire(5);
    is scalar @$out, 0, 'half-close does not trigger close timeout';
}

# ICMP echo request/reply and v6 flows; distinct protocols never merge
{
    my ( $t, $out ) = table();
    $t->add( pkt( 1, '10.0.0.1', 7, '10.0.0.2', 7 ), 0 );
    $t->add( pkt( 1, '10.0.0.2', 7, '10.0.0.1', 7 ), 0.001 );
    $t->add( pkt( 17, '10.0.0.1', 7, '10.0.0.2', 7 ), 0.002 );
    $t->add( pkt( 6, 'fd00::1', 9, 'fd00::2', 80, flags => SYN, vlan => 5 ), 0.003 );
    $t->flush;
    is scalar @$out, 3, 'icmp, udp and tcp are separate flows';
    is_deeply [ @{ $out->[0] }{qw(pkts_fwd pkts_rev)} ], [ 1, 1 ], 'echo pair merged';
    is $out->[2]{src}, 'fd00::1', 'v6 address formatted';
    is $out->[2]{vlan}, 5, 'vlan kept';
}

# close linger is capped at the idle timeout
{
    my ( $t, $out ) = table( idle_timeout => 1, close_timeout => 5 );
    $t->add( pkt( 6, "1.1.1.1", 1, "2.2.2.2", 2, flags => RST ), 0 );
    $t->expire(1);
    is $out->[0]{end}, "close", "closed flow reaped after min(close, idle)";
}

is PcapFlow::FlowTable::flags_str(0xff), 'FSRPAUEC', 'flags_str';

done_testing;
