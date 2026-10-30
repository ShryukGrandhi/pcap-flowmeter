use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/../lib";
use PcapFlow::Gen;
use PcapFlow::Analyzer;
use PcapFlow::Parallel;

my $dir = tempdir( CLEANUP => 1 );

# one capture, and the same capture split into 5 consecutive files
my $g = PcapFlow::Gen->new( seed => 11 )->generate( flows => 600, gap_us => 300 );
PcapFlow::Gen->write_pcap( "$dir/all.pcap", $g );
my @pk = @{ $g->{packets} };
my @files;
my $per = int( @pk / 5 ) + 1;
for my $i ( 0 .. 4 ) {
    my @slice = grep { defined } @pk[ $i * $per .. ( $i + 1 ) * $per - 1 ];
    push @files, "$dir/part$i.pcap";
    PcapFlow::Gen->write_pcap( $files[-1], $g, packets => \@slice );
}

my @CMP = qw(proto src sport dst dport pkts_fwd pkts_rev bytes_fwd bytes_rev tcp_flags);
sub canon {
    my $flows = shift;
    return [ sort map { join '|', ( map { $_ // '' } @$_{@CMP} ), sprintf( '%.6f', $_->{first} ), sprintf( '%.6f', $_->{last} ) } @$flows ];
}

sub serial {
    my ( $opts, @f ) = @_;
    my $an = PcapFlow::Analyzer->new(%$opts);
    $an->process($_) for @f;
    return $an->finish;
}

for my $opts ( {}, { idle_timeout => 0.012 }, { filter => 'tcp and not ip6' } ) {
    my $label = join( ',', map { "$_=$opts->{$_}" } sort keys %$opts ) || 'defaults';
    my $whole = serial( $opts, "$dir/all.pcap" );
    my $split = serial( $opts, @files );
    my $par   = PcapFlow::Parallel::run( files => \@files, jobs => 3, %$opts );

    is_deeply canon( $split->{flows} ), canon( $whole->{flows} ), "$label: serial over split files == one file";
    is_deeply canon( $par->{flows} ), canon( $whole->{flows} ), "$label: parallel -j3 == one file";
    is $par->{stats}{$_}, $whole->{stats}{$_}, "$label: stat $_" for qw(packets bytes matched filtered ipv4 ipv6);
    is $par->{stats}{files}, 5, "$label: 5 files";
    cmp_ok scalar @{ $whole->{flows} }, '>', 0, "$label: produced flows";
}

# the short idle timeout really did split flows, so merging was exercised
{
    my $r = serial( { idle_timeout => 0.012 }, "$dir/all.pcap" );
    cmp_ok scalar @{ $r->{flows} }, '>', 600, 'short idle timeout splits conversations';
}

# a failing worker fails the whole run and names the file
{
    open my $fh, '>', "$dir/bad.pcap" or die;
    print $fh "definitely not a pcap file";
    close $fh;
    my $res = eval { PcapFlow::Parallel::run( files => [ @files[ 0, 1 ], "$dir/bad.pcap", $files[2] ], jobs => 2 ) };
    ok !$res, 'run fails';
    like $@, qr/bad\.pcap: .*not a pcap file/, 'error names the bad file';

    $res = eval { PcapFlow::Parallel::run( files => [ "$dir/missing.pcap", $files[0] ], jobs => 2 ) };
    like $@, qr/missing\.pcap: cannot open/, 'missing file reported';
}

# no zombie children left behind
{
    PcapFlow::Parallel::run( files => \@files, jobs => 5 );
    my $kid = waitpid( -1, 1 );    # WNOHANG
    is $kid, -1, 'all workers reaped';
}

# bad filter is reported before any fork
{
    eval { PcapFlow::Parallel::run( files => \@files, jobs => 2, filter => 'port' ) };
    like $@, qr/expected port number/, 'filter compiled in parent';
}

# merge(): direction-reversed continuation is re-oriented
{
    my $a = { proto => 6, src => '1.1.1.1', sport => 5, dst => '2.2.2.2', dport => 80, first => 0, last => 1,
        pkts_fwd => 2, pkts_rev => 1, bytes_fwd => 100, bytes_rev => 50, tcp_flags => 'SA', end => 'eof', closed => 0 };
    my $b = { proto => 6, src => '2.2.2.2', sport => 80, dst => '1.1.1.1', dport => 5, first => 2, last => 3,
        pkts_fwd => 4, pkts_rev => 3, bytes_fwd => 400, bytes_rev => 300, tcp_flags => 'FPA', end => 'eof', closed => 1, first_syn => 0 };
    my $m = PcapFlow::Parallel::merge( [ $b, $a ] );
    is scalar @$m, 1, 'merged into one';
    is_deeply [ @{ $m->[0] }{qw(src pkts_fwd pkts_rev bytes_fwd bytes_rev tcp_flags last closed)} ],
      [ '1.1.1.1', 2 + 3, 1 + 4, 100 + 300, 50 + 400, 'FSPA', 3, 1 ], 'counters swapped to match orientation';
}

done_testing;
