# Cross-check against the real tcpdump(1): it must read every packet we
# write, and our filter compiler must select exactly the packets that
# libpcap's BPF compiler selects for the same expression.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/../lib";
use PcapFlow::Gen;
use PcapFlow::Analyzer;

my ($tcpdump) = grep { -x } map { "$_/tcpdump" } split( /:/, $ENV{PATH} // '' ), '/usr/sbin', '/usr/bin';
plan skip_all => 'tcpdump not installed' unless $tcpdump;

my $dir  = tempdir( CLEANUP => 1 );
my $file = "$dir/x.pcap";    # .pcap suffix: Ubuntu's AppArmor profile requires it
# no VLAN tags: plain BPF 'tcp' does not look inside 802.1Q frames
my $g = PcapFlow::Gen->new( seed => 99 )->generate( flows => 500, vlan_pct => 0, v6_pct => 30 );
my $n = PcapFlow::Gen->write_pcap( $file, $g );

sub td_count {
    my $expr = shift;
    my @cmd  = ( $tcpdump, '-nn', '-r', $file, length $expr ? $expr : () );
    open my $fh, '-|', @cmd or die "tcpdump: $!";
    my $c = 0;
    $c++ while <$fh>;
    close $fh;
    return $? == 0 ? $c : undef;
}

# make sure tcpdump can actually read files here (sandboxes may block it)
open my $save, ">&", \*STDERR or die;
open STDERR, ">", "/dev/null";
my $all = td_count("");
open STDERR, ">&", $save;
plan skip_all => 'tcpdump cannot read capture files in this environment' unless defined $all;
is $all, $n, "tcpdump reads all $n packets we wrote";

my @exprs = (
    'tcp', 'udp', 'icmp', 'icmp6', 'ip', 'ip6', 'not tcp',
    'port 53', 'port 443', 'dst port 443', 'src port 443', 'portrange 80-443',
    'tcp and dst port 22', 'udp or icmp', 'tcp and (port 80 or port 8080)',
    'host 192.168.0.7', 'src host 192.168.0.7', 'dst host fd00:0:0:1::9',
    'net 10.0.0.0/24', 'dst net 10.0.1.0/24', 'src net 10.0.1.0/24 and udp',
    'net fd00::/16', 'greater 1000', 'less 100', 'proto 17', 'not (tcp or udp)',
);
for my $e (@exprs) {
    my $an = PcapFlow::Analyzer->new( filter => $e );
    $an->process($file);
    my $ours = $an->finish->{stats}{matched};
    open STDERR, '>', '/dev/null';
    my $theirs = td_count($e);
    open STDERR, '>&', $save;
    is $ours, $theirs, "'$e' selects the same packets as tcpdump ($ours)";
}

done_testing;
