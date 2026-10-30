package PcapFlow::Writer;

# Writes classic libpcap files. Used by the traffic generator, the tests and
# the benchmark; output is readable by tcpdump/wireshark.

use strict;
use warnings;
use Carp qw(croak);

sub new {
    my ( $class, %a ) = @_;
    my $fh = $a{fh};
    if ( !$fh ) {
        croak "Writer: need path or fh" unless defined $a{path};
        open $fh, '>', $a{path} or croak "cannot write $a{path}: $!";
    }
    binmode $fh;
    my $ns      = $a{nanosecond} ? 1 : 0;
    my $le      = $a{big_endian} ? 0 : 1;
    my ( $L, $S ) = $le ? ( 'V', 'v' ) : ( 'N', 'n' );
    my $self = bless {
        fh       => $fh,
        snaplen  => $a{snaplen} // 262144,
        linktype => $a{linktype} // 1,
        ticks    => $ns ? 1_000_000_000 : 1_000_000,
        rfmt     => $L x 4,
        count    => 0,
    }, $class;
    my $magic = $ns ? 0xa1b23c4d : 0xa1b2c3d4;
    print {$fh} pack( "$L$S$S$L$L$L$L",
        $magic, 2, 4, 0, 0, $self->{snaplen}, $self->{linktype} )
      or croak "write: $!";
    return $self;
}

sub ticks { $_[0]{ticks} }

# $sec and $frac are integers; $frac is in ticks (usec or nsec).
sub write_packet {
    my ( $self, $sec, $frac, $data, $orig ) = @_;
    $orig //= length $data;
    my $cap = length $data;
    if ( $cap > $self->{snaplen} ) {
        $cap  = $self->{snaplen};
        $data = substr $data, 0, $cap;
    }
    print { $self->{fh} } pack( $self->{rfmt}, $sec, $frac, $cap, $orig ), $data
      or croak "write: $!";
    $self->{count}++;
    return;
}

sub close {
    my $self = shift;
    close $self->{fh} or croak "close: $!";
    return;
}

1;
