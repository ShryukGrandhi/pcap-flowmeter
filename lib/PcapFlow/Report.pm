package PcapFlow::Report;

# Output formatting: human summary, CSV (one flow per line) and JSON.

use strict;
use warnings;
use Exporter 'import';
use JSON::PP ();

our @EXPORT_OK = qw(summary_text csv_header csv_line flows_csv to_json
  top_flows top_talkers);

my %PROTO = ( 1 => 'icmp', 6 => 'tcp', 17 => 'udp', 58 => 'icmp6', 132 => 'sctp' );

my @CSV_COLS = qw(first last proto src sport dst dport pkts_fwd pkts_rev
  bytes_fwd bytes_rev tcp_flags rtt_ms vlan end);

sub proto_name { $PROTO{ $_[0] } // $_[0] }

sub csv_header { join( ',', @CSV_COLS ) . "\n" }

sub csv_line {
    my $f = shift;
    return join( ',',
        sprintf( '%.6f', $f->{first} ), sprintf( '%.6f', $f->{last} ),
        proto_name( $f->{proto} ),
        @$f{qw(src sport dst dport pkts_fwd pkts_rev bytes_fwd bytes_rev tcp_flags)},
        defined $f->{rtt} ? sprintf( '%.3f', $f->{rtt} * 1000 ) : '',
        $f->{vlan} // '', $f->{end} ) . "\n";
}

sub flows_csv {
    my $flows = shift;
    return csv_header() . join '', map { csv_line($_) } @$flows;
}

sub _bytes { $_[0]{bytes_fwd} + $_[0]{bytes_rev} }

sub top_flows {
    my ( $flows, $n ) = @_;
    my @s = sort { _bytes($b) <=> _bytes($a) || $a->{first} <=> $b->{first} } @$flows;
    splice @s, $n if @s > $n;
    return \@s;
}

# Hosts ranked by bytes sent plus received.
sub top_talkers {
    my ( $flows, $n ) = @_;
    my %h;
    for my $f (@$flows) {
        $h{ $f->{src} }{tx} += $f->{bytes_fwd};
        $h{ $f->{src} }{rx} += $f->{bytes_rev};
        $h{ $f->{dst} }{rx} += $f->{bytes_fwd};
        $h{ $f->{dst} }{tx} += $f->{bytes_rev};
        $h{$_}{flows}++ for $f->{src} eq $f->{dst} ? ( $f->{src} ) : ( $f->{src}, $f->{dst} );
    }
    my @rows = map { { host => $_, tx => $h{$_}{tx}, rx => $h{$_}{rx}, flows => $h{$_}{flows} } } keys %h;
    @rows = sort { ( $b->{tx} + $b->{rx} ) <=> ( $a->{tx} + $a->{rx} ) || $a->{host} cmp $b->{host} } @rows;
    splice @rows, $n if @rows > $n;
    return \@rows;
}

sub summary_text {
    my ( $res, %o ) = @_;
    my $s     = $res->{stats};
    my $flows = $res->{flows};
    my $n     = $o{top} // 10;
    my $out   = '';

    $out .= sprintf "packets %d  bytes %d  ipv4 %d  ipv6 %d  non-ip %d  decode-errors %d\n",
      @$s{qw(packets bytes ipv4 ipv6 non_ip errors)};
    $out .= sprintf "matched %d  filtered-out %d  fragments %d  bad-ip-checksum %d  files %d%s\n",
      @$s{qw(matched filtered frags csum_bad files)},
      $s->{truncated_files} ? "  truncated-files $s->{truncated_files}" : '';
    for my $e ( sort keys %{ $res->{errors_by} || {} } ) {
        $out .= sprintf "  error %-28s %d\n", $e, $res->{errors_by}{$e};
    }

    my ( %pc, %ends );
    for my $f (@$flows) {
        my $p = proto_name( $f->{proto} );
        $pc{$p}{flows}++;
        $pc{$p}{pkts}  += $f->{pkts_fwd} + $f->{pkts_rev};
        $pc{$p}{bytes} += _bytes($f);
        $ends{ $f->{end} }++;
    }
    $out .= sprintf "flows %d  (%s)\n", scalar @$flows,
      join( ', ', map { "$_ $ends{$_}" } sort keys %ends ) || 'none';
    $out .= sprintf "  %-6s %8d flows %10d pkts %12d bytes\n", $_, @{ $pc{$_} }{qw(flows pkts bytes)}
      for sort { $pc{$b}{bytes} <=> $pc{$a}{bytes} || $a cmp $b } keys %pc;

    my @rtt = sort { $a <=> $b } map { $_->{rtt} } grep { defined $_->{rtt} } @$flows;
    if (@rtt) {
        $out .= sprintf "tcp handshake rtt (ms): n=%d p50=%.3f p90=%.3f p99=%.3f max=%.3f\n",
          scalar @rtt, map { 1000 * _pct( \@rtt, $_ ) } 50, 90, 99, 100;
    }

    if ( @$flows && $n > 0 ) {
        $out .= "\ntop $n flows by bytes\n";
        $out .= sprintf "  %-5s %-41s %-41s %8s %10s %-8s %s\n",
          qw(proto initiator responder pkts bytes flags end);
        for my $f ( @{ top_flows( $flows, $n ) } ) {
            $out .= sprintf "  %-5s %-41s %-41s %8d %10d %-8s %s\n",
              proto_name( $f->{proto} ), _ep( $f->{src}, $f->{sport} ),
              _ep( $f->{dst}, $f->{dport} ), $f->{pkts_fwd} + $f->{pkts_rev},
              _bytes($f), $f->{tcp_flags} || '-', $f->{end};
        }
    }
    if ( $o{talkers} && @$flows ) {
        $out .= "\ntop $n talkers\n";
        $out .= sprintf "  %-39s %12s %12s %7s\n", qw(host tx_bytes rx_bytes flows);
        $out .= sprintf "  %-39s %12d %12d %7d\n", @$_{qw(host tx rx flows)}
          for @{ top_talkers( $flows, $n ) };
    }
    return $out;
}

sub _ep { $_[0] =~ /:/ ? "[$_[0]]:$_[1]" : "$_[0]:$_[1]" }

# nearest-rank percentile on a sorted list
sub _pct {
    my ( $s, $p ) = @_;
    my $i = int( $p / 100 * @$s + 0.999999 ) - 1;
    $i = 0 if $i < 0;
    $i = $#$s if $i > $#$s;
    return $s->[$i];
}

sub to_json {
    my ( $res, %o ) = @_;
    my @flows = map {
        my %f = %$_;
        $f{proto} = proto_name( $f{proto} );
        $f{rtt_ms} = defined $f{rtt} ? 0 + sprintf( '%.3f', $f{rtt} * 1000 ) : undef;
        $f{$_} = 0 + sprintf( '%.6f', $f{$_} ) for qw(first last);
        delete @f{qw(rtt first_syn closed)};
        \%f;
    } @{ $res->{flows} };
    return JSON::PP->new->canonical->pretty->encode( {
        stats     => $res->{stats},
        errors_by => $res->{errors_by} || {},
        flows     => \@flows,
    } );
}

1;
