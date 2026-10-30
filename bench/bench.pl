#!/usr/bin/env perl
# Benchmark: throughput of each pipeline stage, parallel speed-up across
# files, and flow accuracy against the generator's ground truth.
#
#   perl bench/bench.pl            # 20000 flows (~215k packets)
#   perl bench/bench.pl --quick    # 2000 flows, for CI
use strict;
use warnings;
use FindBin;
use lib "$FindBin::RealBin/../lib";
use Getopt::Long;
use File::Temp qw(tempdir);
use Time::HiRes qw(time);
use POSIX qw(uname);
use PcapFlow::Gen;
use PcapFlow::Reader;
use PcapFlow::Decode qw(decode);
use PcapFlow::Analyzer;
use PcapFlow::Parallel;

my %o = ( flows => 20000, repeat => 3, seed => 42, parts => 4 );
GetOptions(
    'flows=i'  => \$o{flows},
    'repeat=i' => \$o{repeat},
    'parts=i'  => \$o{parts},
    'quick'    => sub { $o{flows} = 2000; $o{repeat} = 1 },
) or die "usage: bench.pl [--flows N] [--repeat N] [--parts N] [--quick]\n";

my $dir = tempdir( CLEANUP => 1 );
my $t0  = time;
my $g   = PcapFlow::Gen->new( seed => $o{seed} )->generate( flows => $o{flows} );
my $file = "$dir/bench.pcap";
my $npk  = PcapFlow::Gen->write_pcap( $file, $g );
my $gen_s = time - $t0;
my $size  = -s $file;

# split into consecutive parts for the parallel runs
my @pk  = @{ $g->{packets} };
my $per = int( @pk / $o{parts} ) + 1;
my @parts;
for my $i ( 0 .. $o{parts} - 1 ) {
    my @slice = grep { defined } @pk[ $i * $per .. ( $i + 1 ) * $per - 1 ];
    push @parts, "$dir/part$i.pcap";
    PcapFlow::Gen->write_pcap( $parts[-1], $g, packets => \@slice );
}
@pk = ();

sub best {
    my $code = shift;
    my $best;
    for ( 1 .. $o{repeat} ) {
        my $t = time;
        $code->();
        my $d = time - $t;
        $best = $d if !defined $best || $d < $best;
    }
    return $best;
}

my @rows;
sub row {
    my ( $name, $secs ) = @_;
    push @rows, [ $name, $secs, $npk / $secs, $size / $secs / 1e6 ];
}

row( 'read records (Reader)', best( sub {
    my $r = PcapFlow::Reader->new( path => $file );
    1 while $r->next_packet;
} ) );

row( 'read + decode L2-L4', best( sub {
    my $r  = PcapFlow::Reader->new( path => $file );
    my $lt = $r->linktype;
    while ( my ( $ts, $d ) = $r->next_packet ) { decode( $lt, $d ) }
} ) );

my $full;
row( 'full pipeline (flows)', best( sub {
    my $an = PcapFlow::Analyzer->new;
    $an->process($file);
    $full = $an->finish;
} ) );

row( "full + filter 'tcp and dst port 443'", best( sub {
    my $an = PcapFlow::Analyzer->new( filter => 'tcp and dst port 443' );
    $an->process($file);
    $an->finish;
} ) );

row( 'full + IPv4 checksum verify', best( sub {
    my $an = PcapFlow::Analyzer->new( verify_checksums => 1 );
    $an->process($file);
    $an->finish;
} ) );

my $serial_parts = best( sub {
    my $an = PcapFlow::Analyzer->new;
    $an->process($_) for @parts;
    $an->finish;
} );
my %par;
my $par_res;
for my $j ( 2, 4 ) {
    next if $j > $o{parts};
    $par{$j} = best( sub { $par_res = PcapFlow::Parallel::run( files => \@parts, jobs => $j ) } );
}

# accuracy vs ground truth
sub key { join '|', @{ $_[0] }{qw(proto src sport dst dport)} }
my %got = map { key($_) => $_ } @{ $full->{flows} };
my ( $exact, $found ) = ( 0, 0 );
for my $t ( @{ $g->{truth} } ) {
    my $f = $got{ key($t) } or next;
    $found++;
    my $ok = 1;
    $ok &&= $f->{$_} == $t->{$_} for qw(pkts_fwd pkts_rev bytes_fwd bytes_rev);
    $ok &&= abs( $f->{first} - $t->{first_us} / 1e6 ) < 2e-6 && abs( $f->{last} - $t->{last_us} / 1e6 ) < 2e-6;
    $exact++ if $ok;
}
my $ntruth = @{ $g->{truth} };
my %pkey = map { key($_) . sprintf( '|%d|%d', $_->{pkts_fwd}, $_->{bytes_fwd} ) => 1 } @{ $par_res->{flows} };
my $par_same = grep { $pkey{ key($_) . sprintf( '|%d|%d', $_->{pkts_fwd}, $_->{bytes_fwd} ) } } @{ $full->{flows} };

my $ncpu = `getconf _NPROCESSORS_ONLN 2>/dev/null` || `sysctl -n hw.ncpu 2>/dev/null` || '?';
chomp $ncpu;
my @u = uname();
printf "pcap-flowmeter benchmark  (perl %vd, %s %s, %s CPUs)\n", $^V, $u[0], $u[4], $ncpu;
printf "input: %d flows, %d packets, %.1f MB pcap (generated in %.2f s); best of %d runs\n\n",
  $ntruth, $npk, $size / 1e6, $gen_s, $o{repeat};
printf "| %-38s | %8s | %12s | %8s |\n", 'stage', 'seconds', 'packets/s', 'MB/s';
printf "|%s|%s|%s|%s|\n", '-' x 40, '-' x 10, '-' x 14, '-' x 10;
printf "| %-38s | %8.3f | %12.0f | %8.1f |\n", @$_ for @rows;
printf "\nparallel, %d consecutive files:\n", $o{parts};
printf "| %-38s | %8s | %12s | %8s |\n", 'mode', 'seconds', 'packets/s', 'speed-up';
printf "|%s|%s|%s|%s|\n", '-' x 40, '-' x 10, '-' x 14, '-' x 10;
printf "| %-38s | %8.3f | %12.0f | %7.2fx |\n", 'serial (one process)', $serial_parts, $npk / $serial_parts, 1;
printf "| %-38s | %8.3f | %12.0f | %7.2fx |\n", "fork, -j $_", $par{$_}, $npk / $par{$_}, $serial_parts / $par{$_}
  for sort { $a <=> $b } keys %par;
printf "\naccuracy vs generator ground truth: %d/%d flows found, %d/%d exact "
  . "(packets, bytes, first/last time) = %.2f%%\n", $found, $ntruth, $exact, $ntruth, 100 * $exact / $ntruth;
printf "flows reported: %d (single file), %d (parallel, after merging file-boundary splits); "
  . "%d/%d identical\n", scalar @{ $full->{flows} }, scalar @{ $par_res->{flows} }, $par_same,
  scalar @{ $full->{flows} };
exit( $exact == $ntruth && $par_same == @{ $full->{flows} } ? 0 : 1 );
