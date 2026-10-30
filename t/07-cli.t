use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use JSON::PP;

my $root = "$FindBin::Bin/..";
my $dir  = tempdir( CLEANUP => 1 );
my @perl = ( $^X, "-I$root/lib" );
my $gen  = "$root/bin/pcapgen";
my $cli  = "$root/bin/pcapflow";

sub run {
    my $cmd = shift;
    my $out = `$cmd 2>$dir/stderr`;
    my $rc  = $? >> 8;
    open my $fh, '<', "$dir/stderr" or die;
    local $/;
    my $err = <$fh> // '';
    return ( $out, $rc, $err );
}

my ( $out, $rc, $err ) = run("@perl $gen --flows 300 --seed 5 -o $dir/a.pcap --truth $dir/truth.csv");
is $rc, 0, 'pcapgen exit 0';
like $err, qr/300 flows, \d+ packets/, 'pcapgen reports counts';
my @truth = do { open my $fh, '<', "$dir/truth.csv" or die; <$fh> };
is scalar @truth, 301, 'truth csv has header + 300 rows';

( $out, $rc ) = run("@perl $cli $dir/a.pcap");
is $rc, 0, 'text exit 0';
like $out, qr/^flows 300  \(eof 300\)$/m, 'text summary flow count';
like $out, qr/top 10 flows by bytes/, 'top flows section';

( $out, $rc ) = run("@perl $cli -F csv $dir/a.pcap");
my @rows = split /\n/, $out;
is scalar @rows, 301, 'csv: header + one row per flow';
like $rows[0], qr/^first,last,proto,src,sport,dst,dport,/, 'csv header';

( $out, $rc ) = run("@perl $cli -F json -f 'udp' $dir/a.pcap");
my $j = decode_json($out);
ok !grep( { $_->{proto} ne 'udp' } @{ $j->{flows} } ), 'json + filter: only udp flows';
is $j->{stats}{matched} + $j->{stats}{filtered}, $j->{stats}{packets}, 'matched + filtered = packets';

# stdin, in a pipeline, matches reading the file directly
my ($direct) = run("@perl $cli -F csv $dir/a.pcap");
( $out, $rc ) = run("cat $dir/a.pcap | @perl $cli -F csv -");
is $out, $direct, 'reading from a pipe gives identical output';

# pcapgen to stdout straight into pcapflow
( $out, $rc ) = run("@perl $gen --flows 300 --seed 5 -o - 2>/dev/null | @perl $cli -F csv -");
is $out, $direct, 'pcapgen | pcapflow pipeline';

# streaming mode emits rows as flows expire, and works with head(1)
( $out, $rc ) = run("@perl $cli --stream --idle-timeout 0.01 $dir/a.pcap");
my @s = split /\n/, $out;
cmp_ok scalar @s, '>', 300, 'stream with short idle timeout emits split flows';
( $out, $rc ) = run("@perl $cli --stream $dir/a.pcap | head -3");
is scalar( split /\n/, $out ), 3, 'stream piped into head';

# parallel across files
PcapFlowGenSplit: {
    system( "@perl $gen --flows 200 --seed $_ -o $dir/p$_.pcap 2>/dev/null" ) == 0 or die for 1 .. 3;
    my ($ser) = run("@perl $cli -F csv $dir/p1.pcap $dir/p2.pcap $dir/p3.pcap");
    my ($par) = run("@perl $cli -F csv -j 3 $dir/p1.pcap $dir/p2.pcap $dir/p3.pcap");
    my @a = sort split /\n/, $ser;
    my @b = sort split /\n/, $par;
    is_deeply \@b, \@a, '-j 3 output equals serial output';
}

# errors and exit codes
( $out, $rc, $err ) = run("@perl $cli $dir/nope.pcap");
is $rc, 1, 'missing file: exit 1';
like $err, qr/^pcapflow: cannot open .*nope\.pcap/, 'missing file: message';
( $out, $rc, $err ) = run("@perl $cli -f 'port' $dir/a.pcap");
is $rc, 1, 'bad filter: exit 1';
like $err, qr/expected port number/, 'bad filter: message';
( $out, $rc ) = run("@perl $cli");
is $rc, 2, 'no args: usage exit 2';
( $out, $rc ) = run("@perl $cli --help");
is $rc, 0, '--help exit 0';
like $out, qr/^usage: pcapflow/, '--help text';
( $out, $rc, $err ) = run("@perl $cli -j 2 - $dir/a.pcap");
is $rc, 255, 'stdin with -j refused';

done_testing;
