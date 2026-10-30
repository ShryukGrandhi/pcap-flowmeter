package PcapFlow::FlowTable;

# Bidirectional 5-tuple flow table with NetFlow-style expiry.
#
# Both directions of a conversation map to one canonical key (the two
# endpoints sorted bytewise). The initiator is the sender of the first
# packet, unless that packet is a TCP SYN/ACK, in which case the capture
# started mid-handshake and the receiver is the initiator.
#
# A flow ends when:
#   - no packet has been seen for idle_timeout seconds          (end=idle)
#   - TCP saw RST or FIN in both directions, then close_timeout
#     seconds pass without packets (lets the last ACK be counted;
#     capped at idle_timeout)                                     (end=close)
#   - a fresh SYN arrives on a closed TCP flow (port reuse)       (end=reuse)
#   - the input ends                                              (end=eof)
#
# Expiry uses two lazy deadline queues (one per timeout). Each flow is
# enqueued once with first_seen + timeout. When an entry reaches the head
# and its deadline has passed, the flow's real deadline (last_seen +
# timeout) is checked; if the flow was active since, it is re-queued with
# the new deadline. Updating a flow on every packet is O(1) and no periodic
# full-table scan is needed. A packet that arrives for a flow which is past
# its deadline but not yet reaped is detected on lookup, so expiry is exact
# regardless of when the queues are processed.

use strict;
use warnings;
use PcapFlow::Decode qw(addr_to_str);

use constant { TH_FIN => 0x01, TH_SYN => 0x02, TH_RST => 0x04, TH_ACK => 0x10 };

my @FLAG_CHARS = qw(F S R P A U E C);

sub new {
    my ( $class, %o ) = @_;
    my $self = bless {
        idle_timeout  => $o{idle_timeout}  // 60,
        close_timeout => $o{close_timeout} // 5,
        on_export     => $o{on_export},
        flows         => {},
        q_idle        => [],
        q_close       => [],
        h_idle        => 0,
        h_close       => 0,
        next_check    => 0,
        created       => 0,
        exported      => 0,
        peak          => 0,
        active        => 0,
    }, $class;
    # a closed flow never lingers longer than an idle one would
    $self->{close_timeout} = $self->{idle_timeout}
      if $self->{close_timeout} > $self->{idle_timeout};
    return $self;
}

sub active   { $_[0]{active} }
sub created  { $_[0]{created} }
sub exported { $_[0]{exported} }
sub peak     { $_[0]{peak} }

sub add {
    my ( $self, $p, $ts ) = @_;

    if ( $ts >= $self->{next_check} ) {
        $self->expire($ts);
        $self->{next_check} = $ts + 1;
    }

    my $proto = $p->{proto};
    my $ea    = $p->{src} . pack( 'n', $p->{sport} );
    my $eb    = $p->{dst} . pack( 'n', $p->{dport} );
    my ( $key, $side );    # side: 0 if the sender is canonical endpoint A
    if ( ( $ea cmp $eb ) <= 0 ) { $key = chr($proto) . $ea . $eb; $side = 0 }
    else                        { $key = chr($proto) . $eb . $ea; $side = 1 }

    my $fl = $proto == 6 ? $p->{tcp_flags} : 0;
    my $f  = $self->{flows}{$key};
    if ($f) {
        if ( $f->{closed} ) {
            if ( $ts - $f->{last} >= $self->{close_timeout} ) {
                $self->_export( $f, 'close' );
                undef $f;
            }
            elsif ( ( $fl & ( TH_SYN | TH_ACK ) ) == TH_SYN ) {
                $self->_export( $f, 'reuse' );
                undef $f;
            }
        }
        elsif ( $ts - $f->{last} >= $self->{idle_timeout} ) {
            $self->_export( $f, 'idle' );
            undef $f;
        }
    }

    if ( !$f ) {
        my $init = $side;
        $init = 1 - $side if ( $fl & ( TH_SYN | TH_ACK ) ) == ( TH_SYN | TH_ACK );
        my ( $a, $b ) = $side == 0 ? ( $p->{src}, $p->{dst} ) : ( $p->{dst}, $p->{src} );
        my ( $pa, $pb ) = $side == 0 ? ( $p->{sport}, $p->{dport} ) : ( $p->{dport}, $p->{sport} );
        $f = {
            key       => $key,
            proto     => $proto,
            l3        => $p->{l3},
            init      => $init,
            a         => $a,
            pa        => $pa,
            b         => $b,
            pb        => $pb,
            first     => $ts,
            last      => $ts,
            pf        => 0,
            pr        => 0,
            bf        => 0,
            br        => 0,
            flags     => 0,
            first_fl  => $fl,
            vlan      => $p->{vlan},
            closed    => 0,
        };
        $self->{flows}{$key} = $f;
        push @{ $self->{q_idle} }, [ $ts + $self->{idle_timeout}, $f ];
        $self->{created}++;
        $self->{peak} = $self->{active} if ++$self->{active} > $self->{peak};
    }

    my $fwd = $side == $f->{init};
    if   ($fwd) { $f->{pf}++; $f->{bf} += $p->{ip_len} }
    else        { $f->{pr}++; $f->{br} += $p->{ip_len} }
    $f->{last} = $ts if $ts > $f->{last};

    if ( $proto == 6 ) {
        $f->{flags} |= $fl;
        # Handshake time = SYN (initiator) -> SYN/ACK -> ACK (initiator).
        # Measured SYN to final ACK it equals one full round trip no matter
        # where on the path the capture was taken.
        if ( ( $fl & ( TH_SYN | TH_ACK ) ) == TH_SYN ) {
            $f->{syn_ts} //= $ts if $fwd;
        }
        elsif ( ( $fl & ( TH_SYN | TH_ACK ) ) == ( TH_SYN | TH_ACK ) ) {
            $f->{synack_ts} //= $ts if !$fwd && defined $f->{syn_ts};
        }
        elsif ( ( $fl & TH_ACK ) && $fwd && defined $f->{synack_ts} ) {
            $f->{rtt} //= $ts - $f->{syn_ts};
        }

        if ( !$f->{closed} ) {
            if ( $fl & TH_FIN ) { $f->{ $fwd ? 'fin_f' : 'fin_r' } = 1 }
            if ( ( $fl & TH_RST ) || ( $f->{fin_f} && $f->{fin_r} ) ) {
                $f->{closed} = 1;
                push @{ $self->{q_close} }, [ $ts + $self->{close_timeout}, $f ];
            }
        }
    }
    return $f;
}

# Export every flow whose deadline is at or before $now.
sub expire {
    my ( $self, $now ) = @_;
    $self->_drain( 'q_idle',  'h_idle',  $self->{idle_timeout},  $now, 0 );
    $self->_drain( 'q_close', 'h_close', $self->{close_timeout}, $now, 1 );
    return;
}

sub _drain {
    my ( $self, $qn, $hn, $tmo, $now, $closed_q ) = @_;
    my $q = $self->{$qn};
    my $h = $self->{$hn};
    while ( $h < @$q && $q->[$h][0] <= $now ) {
        my $f = $q->[ $h++ ][1];
        next if $f->{done};
        next if $closed_q && !$f->{closed};
        # a closed flow is reaped by the close queue, which is always sooner
        next if !$closed_q && $f->{closed};
        my $deadline = $f->{last} + $tmo;
        if ( $deadline <= $now ) {
            $self->_export( $f, $closed_q ? 'close' : 'idle' );
        }
        else {
            push @$q, [ $deadline, $f ];
        }
    }
    # compact the consumed prefix once it dominates the array
    if ( $h > 4096 && $h * 2 > @$q ) {
        splice @$q, 0, $h;
        $h = 0;
    }
    $self->{$hn} = $h;
    return;
}

# Export all remaining flows (end of input), oldest first.
sub flush {
    my ( $self, $reason ) = @_;
    my @left = sort { $a->{first} <=> $b->{first} || $a->{key} cmp $b->{key} }
      values %{ $self->{flows} };
    $self->_export( $_, $reason // 'eof' ) for @left;
    @{ $self->{q_idle} } = @{ $self->{q_close} } = ();
    $self->{h_idle} = $self->{h_close} = 0;
    return;
}

sub _export {
    my ( $self, $f, $reason ) = @_;
    $f->{done} = 1;
    delete $self->{flows}{ $f->{key} };
    $self->{active}--;
    $self->{exported}++;
    my $rec = to_record( $f, $reason );
    $self->{on_export}->($rec) if $self->{on_export};
    return;
}

sub flags_str {
    my $fl = shift;
    return join '', map { $fl & ( 1 << $_ ) ? $FLAG_CHARS[$_] : () } 0 .. 7;
}

# Plain record with printable addresses, oriented initiator -> responder.
sub to_record {
    my ( $f, $reason ) = @_;
    my ( $sa, $sp, $da, $dp ) = $f->{init} == 0
      ? ( $f->{a}, $f->{pa}, $f->{b}, $f->{pb} )
      : ( $f->{b}, $f->{pb}, $f->{a}, $f->{pa} );
    return {
        proto     => $f->{proto},
        src       => addr_to_str($sa),
        sport     => $sp,
        dst       => addr_to_str($da),
        dport     => $dp,
        first     => $f->{first},
        last      => $f->{last},
        pkts_fwd  => $f->{pf},
        pkts_rev  => $f->{pr},
        bytes_fwd => $f->{bf},
        bytes_rev => $f->{br},
        tcp_flags => flags_str( $f->{flags} ),
        rtt       => $f->{rtt},
        vlan      => $f->{vlan},
        closed    => $f->{closed},
        first_syn => ( ( $f->{first_fl} & ( TH_SYN | TH_ACK ) ) == TH_SYN ) ? 1 : 0,
        end       => $reason,
    };
}

1;
