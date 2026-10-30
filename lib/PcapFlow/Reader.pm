package PcapFlow::Reader;

# Streaming reader for classic libpcap capture files (the format written by
# `tcpdump -w`). Handles both byte orders and the microsecond/nanosecond
# timestamp variants. Works on any filehandle, so it reads from pipes too.

use strict;
use warnings;
use Carp qw(croak);

use constant MAX_CAPLEN => 64 * 1024 * 1024;

# magic as read little-endian => [little_endian, ticks_per_second]
my %MAGIC = (
    0xa1b2c3d4 => [ 1, 1_000_000 ],
    0xa1b23c4d => [ 1, 1_000_000_000 ],
    0xd4c3b2a1 => [ 0, 1_000_000 ],
    0x4d3cb2a1 => [ 0, 1_000_000_000 ],
);

sub new {
    my ( $class, %a ) = @_;
    my $fh = $a{fh};
    my $name = $a{path} // '<fh>';
    if ( !$fh ) {
        croak "Reader: need path or fh" unless defined $a{path};
        if ( $a{path} eq '-' ) {
            $fh = \*STDIN;
        }
        else {
            open $fh, '<', $a{path} or croak "cannot open $a{path}: $!";
        }
    }
    binmode $fh;
    my $self = bless { fh => $fh, name => $name, count => 0, truncated => 0 },
      $class;
    $self->_read_global_header;
    return $self;
}

sub _read_global_header {
    my $self = shift;
    my $n    = read( $self->{fh}, my $hdr, 24 );
    croak "$self->{name}: read error: $!" unless defined $n;
    croak "$self->{name}: file too short for pcap header ($n bytes)" if $n < 24;

    my $magic = unpack 'V', $hdr;
    if ( $magic == 0x0a0d0d0a ) {
        croak "$self->{name}: pcapng is not supported; convert with "
          . "`editcap -F pcap in.pcapng out.pcap`";
    }
    my $m = $MAGIC{$magic}
      or croak sprintf "%s: not a pcap file (magic 0x%08x)", $self->{name}, $magic;
    my ( $le, $ticks ) = @$m;
    my ( $L, $S ) = $le ? ( 'V', 'v' ) : ( 'N', 'n' );

    my ( $vmaj, $vmin, $zone, $sigfigs, $snaplen, $network ) =
      unpack "$S$S$L$L$L$L", substr( $hdr, 4 );

    @$self{qw(little_endian ticks version snaplen linktype)} =
      ( $le, $ticks, "$vmaj.$vmin", $snaplen, $network & 0x03ffffff );
    $self->{rfmt} = $L x 4;
    return;
}

sub linktype      { $_[0]{linktype} }
sub snaplen       { $_[0]{snaplen} }
sub nanosecond    { $_[0]{ticks} == 1_000_000_000 }
sub little_endian { $_[0]{little_endian} }
sub count         { $_[0]{count} }
sub truncated     { $_[0]{truncated} }

# Returns (timestamp_seconds_float, captured_bytes, original_length),
# or an empty list at end of file. A partial trailing record (as left by a
# capture that was killed mid-write) ends the stream and sets ->truncated.
sub next_packet {
    my $self = shift;
    my $fh   = $self->{fh};

    my $n = read( $fh, my $rh, 16 );
    croak "$self->{name}: read error: $!" unless defined $n;
    return if $n == 0;
    if ( $n < 16 ) { $self->{truncated} = 1; return }

    my ( $sec, $frac, $incl, $orig ) = unpack $self->{rfmt}, $rh;
    if ( $incl > MAX_CAPLEN ) {
        croak sprintf "%s: corrupt record %d (caplen %d)", $self->{name},
          $self->{count} + 1, $incl;
    }
    my $data = '';
    if ($incl) {
        $n = read( $fh, $data, $incl );
        croak "$self->{name}: read error: $!" unless defined $n;
        if ( $n < $incl ) { $self->{truncated} = 1; return }
    }
    $self->{count}++;
    return ( $sec + $frac / $self->{ticks}, $data, $orig );
}

1;
