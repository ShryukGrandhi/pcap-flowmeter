use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/../lib";
use PcapFlow::Gen;
use PcapFlow::Analyzer;

my $dir = tempdir( CLEANUP => 1 );

sub key { join '|', @{ $_[0] }{qw(proto src sport dst dport)} }

for my $lt ( [ ethernet => 1 ], [ sll => 113 ], [ sll2 => 276 ], [ raw => 101 ] ) {
    my ( $name, $code ) = @$lt;
    my $g = PcapFlow::Gen->new( seed => 7 + $code )->generate( flows => 400, linktype => $code, vlan_pct => 25 );
    my $path = "$dir/$name.pcap";
    my $n = PcapFlow::Gen->write_pcap( $path, $g );

    my $an = PcapFlow::Analyzer->new( verify_checksums => 1 );
    $an->process($path);
    my $res = $an->finish;
    my $s   = $res->{stats};

    is $s->{packets}, $n, "$name: every packet read";
    is $s->{errors} + $s->{csum_bad} + $s->{non_ip}, 0, "$name: no errors, all IPv4 checksums valid";
    is scalar @{ $res->{flows} }, scalar @{ $g->{truth} }, "$name: flow count matches ground truth";

    my %got = map { key($_) => $_ } @{ $res->{flows} };
    my ( $exact, $tcp, $rtt ) = ( 0, 0, 0 );
    for my $t ( @{ $g->{truth} } ) {
        my $f = $got{ key($t) } or next;
        my $same = 1;
        $same &&= $f->{$_} == $t->{$_} for qw(pkts_fwd pkts_rev bytes_fwd bytes_rev);
        $same &&= abs( $f->{first} - $t->{first_us} / 1e6 ) < 2e-6;
        $same &&= abs( $f->{last} - $t->{last_us} / 1e6 ) < 2e-6;
        $same &&= ( $f->{vlan} // -1 ) == ( $t->{vlan} // -1 );
        $exact++ if $same;
        if ( $t->{proto} == 6 ) {
            $tcp++;
            $rtt++ if defined $f->{rtt} && $f->{tcp_flags} eq 'FSPA';
        }
    }
    is $exact, scalar @{ $g->{truth} }, "$name: every flow's packets, bytes, times and vlan exact";
    is $rtt, $tcp, "$name: every TCP flow has a handshake RTT and full flag set";
}

# generator is deterministic
{
    my $a = PcapFlow::Gen->new( seed => 3 )->generate( flows => 50 );
    my $b = PcapFlow::Gen->new( seed => 3 )->generate( flows => 50 );
    my $c = PcapFlow::Gen->new( seed => 4 )->generate( flows => 50 );
    is_deeply $a, $b, 'same seed, same capture';
    ok !eq_array( [ map { $_->[2] } @{ $a->{packets} } ], [ map { $_->[2] } @{ $c->{packets} } ] ),
      'different seed, different capture';
}

done_testing;
