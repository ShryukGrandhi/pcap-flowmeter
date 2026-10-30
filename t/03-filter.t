use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib", "$FindBin::Bin/lib";
use Craft;
use PcapFlow::Decode qw(decode);
use PcapFlow::Filter;

my %P = (
    web   => decode( 1, eth( ipv4( '10.0.0.5', '93.184.216.34', 6, tcp( 51000, 443, 0x18, 200 ) ) ) ),
    dns   => decode( 1, eth( ipv4( '10.0.0.5', '8.8.8.8', 17, udp( 40000, 53, 30 ) ), 20 ) ),
    ping  => decode( 1, eth( ipv4( '10.0.0.5', '10.0.0.1', 1, icmp( 8, 0, 9 ) ) ) ),
    v6ssh => decode( 1, eth( ipv6( '2001:db8::5', '2001:db8:1::9', 6, tcp( 22, 60000, 0x10 ) ) ) ),
    ping6 => decode( 1, eth( ipv6( 'fe80::1', 'fe80::2', 58, icmp( 128, 0, 1 ) ) ) ),
    frag  => decode( 1, eth( ipv4( '172.16.0.1', '172.16.0.2', 17, "\0" x 40, 0x0010 ) ) ),
);
$P{web}{len} = 300;

my @cases = (
    [ 'tcp',                           [qw(web v6ssh)] ],
    [ 'udp',                           [qw(dns frag)] ],
    [ 'icmp',                          [qw(ping)] ],
    [ 'icmp6',                         [qw(ping6)] ],
    [ 'ip6',                           [qw(v6ssh ping6)] ],
    [ 'ip and not udp',                [qw(web ping)] ],
    [ 'port 53',                       [qw(dns)] ],
    [ 'port 9',                        [] ],                     # icmp id is not a port
    [ 'dst port 443',                  [qw(web)] ],
    [ 'src port 443',                  [] ],
    [ 'portrange 20-60',               [qw(dns v6ssh)] ],
    [ 'host 10.0.0.5',                 [qw(web dns ping)] ],
    [ 'src host 10.0.0.1',             [] ],
    [ 'dst host 10.0.0.1',             [qw(ping)] ],
    [ 'host 2001:db8::5',              [qw(v6ssh)] ],
    [ 'net 10.0.0.0/8',                [qw(web dns ping)] ],
    [ 'dst net 8.8.0.0/16',            [qw(dns)] ],
    [ 'net 2001:db8::/32',             [qw(v6ssh)] ],
    [ 'src net 2001:db8:1::/48',       [] ],
    [ 'net 0.0.0.0/0',                 [qw(web dns ping frag)] ],  # v4 only
    [ 'vlan',                          [qw(dns)] ],
    [ 'vlan 20',                       [qw(dns)] ],
    [ 'vlan 21',                       [] ],
    [ 'frag',                          [qw(frag)] ],
    [ 'proto 17',                      [qw(dns frag)] ],
    [ 'greater 200',                   [qw(web)] ],
    [ 'less 100',                      [qw(dns ping v6ssh ping6 frag)] ],
    [ 'tcp or icmp',                   [qw(web v6ssh ping)] ],
    [ 'tcp and port 22 or icmp6',      [qw(v6ssh ping6)] ],
    [ 'tcp and (port 22 or port 53)',  [qw(v6ssh)] ],
    [ '!tcp && !udp',                  [qw(ping ping6)] ],
    [ 'not (tcp || udp) and ip',       [qw(ping)] ],
    [ 'not not tcp',                   [qw(web v6ssh)] ],
);

for my $c (@cases) {
    my ( $expr, $want ) = @$c;
    my $f   = PcapFlow::Filter->new($expr);
    my @got = grep { $f->match( $P{$_} ) } sort keys %P;
    is_deeply \@got, [ sort @$want ], "'$expr'" or diag $f->source;
}

{
    my $f = PcapFlow::Filter->new('udp or tcp and port 9999');
    ok $f->match( $P{dns} ), 'precedence: udp matches without port';
    ok !$f->match( $P{web} ), 'precedence: tcp needs the port';
}

# literals are not interpolated into generated code
unlike( PcapFlow::Filter->new('host 10.0.0.5')->source, qr/10\.0/, 'address kept out of source' );

my @bad = (
    [ 'tcp and',          qr/unexpected end/ ],
    [ 'port',             qr/expected port number/ ],
    [ 'port 70000',       qr/out of range/ ],
    [ 'host 1.2.3',       qr/expected IP address/ ],
    [ 'net 10.0.0.0/33',  qr/too long/ ],
    [ 'net 10.0.0.0',     qr/address\/prefix/ ],
    [ '(tcp',             qr/expected '\)'/ ],
    [ 'tcp)',             qr/unexpected '\)'/ ],
    [ 'banana',           qr/unknown primitive 'banana'/ ],
    [ 'src tcp',          qr/unknown primitive 'tcp'/ ],
    [ 'portrange 50-10',  qr/bad portrange/ ],
    [ 'tcp udp',          qr/unexpected 'udp'/ ],
    [ 'host 1.1.1.1; system("x")', qr/expected IP address|unexpected/ ],
    [ '',                 qr/empty expression/ ],
);
for my $b (@bad) {
    eval { PcapFlow::Filter->new( $b->[0] ) };
    like $@, $b->[1], "rejects '$b->[0]'";
}

done_testing;
