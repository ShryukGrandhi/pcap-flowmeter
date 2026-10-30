use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use PcapFlow::Reader;
use PcapFlow::Writer;

my $dir = tempdir( CLEANUP => 1 );

sub roundtrip {
    my %wopt = @_;
    my $path = "$dir/rt.pcap";
    my $w    = PcapFlow::Writer->new( path => $path, linktype => 113, %wopt );
    my $frac = $w->ticks == 1e9 ? 123456789 : 123456;
    $w->write_packet( 1700000000, $frac, "abc" );
    $w->write_packet( 1700000001, 0, "x" x 100, 1500 );
    $w->write_packet( 1700000002, 5, "" );
    $w->close;
    return PcapFlow::Reader->new( path => $path );
}

for my $case ( [ 'le usec', {} ], [ 'be usec', { big_endian => 1 } ],
    [ 'le nsec', { nanosecond => 1 } ], [ 'be nsec', { big_endian => 1, nanosecond => 1 } ] )
{
    my ( $name, $o ) = @$case;
    my $r = roundtrip(%$o);
    is $r->linktype, 113, "$name: linktype";
    is !!$r->little_endian, !$o->{big_endian}, "$name: byte order detected";
    is !!$r->nanosecond, !!$o->{nanosecond}, "$name: timestamp resolution";
    my @p = $r->next_packet;
    my $want = $o->{nanosecond} ? 1700000000.123456789 : 1700000000.123456;
    cmp_ok abs( $p[0] - $want ), '<', 1e-6, "$name: timestamp";
    is $p[1], 'abc', "$name: data";
    is $p[2], 3, "$name: orig len defaults to caplen";
    @p = $r->next_packet;
    is length $p[1], 100, "$name: caplen";
    is $p[2], 1500, "$name: orig len kept";
    @p = $r->next_packet;
    is $p[1], '', "$name: zero-length record";
    is scalar( () = $r->next_packet ), 0, "$name: eof";
    is $r->count, 3, "$name: count";
    ok !$r->truncated, "$name: not truncated";
}

# snaplen clipping on write
{
    my $w = PcapFlow::Writer->new( path => "$dir/snap.pcap", snaplen => 10 );
    $w->write_packet( 1, 0, "y" x 50 );
    $w->close;
    my @p = PcapFlow::Reader->new( path => "$dir/snap.pcap" )->next_packet;
    is length $p[1], 10, 'writer clips to snaplen';
    is $p[2], 50, 'orig length preserved';
}

# truncated trailing record (capture killed mid-write)
{
    my $w = PcapFlow::Writer->new( path => "$dir/tr.pcap" );
    $w->write_packet( 1, 0, "z" x 40 ) for 1 .. 3;
    $w->close;
    my $size = -s "$dir/tr.pcap";
    truncate "$dir/tr.pcap", $size - 10 or die $!;
    my $r = PcapFlow::Reader->new( path => "$dir/tr.pcap" );
    my $n = 0;
    $n++ while $r->next_packet;
    is $n, 2, 'complete records before truncation are returned';
    ok $r->truncated, 'truncation flagged';
}

# bad inputs
{
    open my $fh, '>', "$dir/ng.pcap" or die;
    print $fh pack( 'V', 0x0a0d0d0a ), "\0" x 40;
    close $fh;
    eval { PcapFlow::Reader->new( path => "$dir/ng.pcap" ) };
    like $@, qr/pcapng is not supported/, 'pcapng rejected with a hint';

    open $fh, '>', "$dir/junk" or die;
    print $fh "hello world, this is not a capture";
    close $fh;
    eval { PcapFlow::Reader->new( path => "$dir/junk" ) };
    like $@, qr/not a pcap file/, 'bad magic rejected';

    open $fh, '>', "$dir/short" or die;
    print $fh "abc";
    close $fh;
    eval { PcapFlow::Reader->new( path => "$dir/short" ) };
    like $@, qr/too short/, 'short header rejected';

    my $w = PcapFlow::Writer->new( path => "$dir/huge.pcap" );
    print { $w->{fh} } pack( 'V4', 1, 0, 0x7fffffff, 0x7fffffff );
    $w->close;
    eval { PcapFlow::Reader->new( path => "$dir/huge.pcap" )->next_packet };
    like $@, qr/corrupt record 1/, 'absurd caplen rejected';
}

# reading from a pipe (as in `tcpdump -w - | pcapflow -`)
SKIP: {
    skip 'no cat(1)', 2 unless -x '/bin/cat';
    my $w = PcapFlow::Writer->new( path => "$dir/pipe.pcap" );
    $w->write_packet( $_, 0, "p" x 3000 ) for 1 .. 50;
    $w->close;
    open my $fh, '-|', '/bin/cat', "$dir/pipe.pcap" or die $!;
    my $r = PcapFlow::Reader->new( fh => $fh );
    my $n = 0;
    while ( my @p = $r->next_packet ) { $n++ if length $p[1] == 3000 }
    close $fh;
    is $n, 50, 'all records read intact through a pipe';
    is $?, 0, 'cat exited cleanly';
}

done_testing;
