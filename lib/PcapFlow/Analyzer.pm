package PcapFlow::Analyzer;

# Glue between the reader, decoder, filter and flow table. Feed it one or
# more capture files (or filehandles) in time order; flow state carries over
# from one file to the next, as with a tcpdump -C/-G rotated capture.

use strict;
use warnings;
use Carp qw(croak);
use PcapFlow::Reader;
use PcapFlow::Decode qw(decode supported_linktype linktype_name);
use PcapFlow::Filter;
use PcapFlow::FlowTable;

my @STAT_KEYS = qw(packets bytes ipv4 ipv6 non_ip errors csum_bad frags
  matched filtered truncated_files files);

sub stat_keys { @STAT_KEYS }

sub new {
    my ( $class, %o ) = @_;
    my $self = bless {
        verify  => $o{verify_checksums} ? 1 : 0,
        flows   => [],
        stats   => { map { $_ => 0 } @STAT_KEYS },
        errors_by => {},
    }, $class;
    if ( defined $o{filter} && length $o{filter} ) {
        $self->{filter} = PcapFlow::Filter->new( $o{filter} )->code;
    }
    my $on_flow = $o{on_flow};
    my $flows   = $self->{flows};
    $self->{table} = PcapFlow::FlowTable->new(
        idle_timeout  => $o{idle_timeout},
        close_timeout => $o{close_timeout},
        on_export     => $on_flow ? $on_flow : sub { push @$flows, $_[0] },
    );
    return $self;
}

sub table { $_[0]{table} }
sub stats { $_[0]{stats} }

# $src: a path ('-' for stdin) or an open filehandle
sub process {
    my ( $self, $src ) = @_;
    my $r = ref $src ? PcapFlow::Reader->new( fh => $src )
                     : PcapFlow::Reader->new( path => $src );
    my $lt = $r->linktype;
    croak( ( ref $src ? 'input' : $src ) . ': unsupported ' . linktype_name($lt) )
      unless supported_linktype($lt);

    my ( $s, $filter, $table, $verify ) = @$self{qw(stats filter table verify)};
    my $eb = $self->{errors_by};
    $s->{files}++;
    while ( my ( $ts, $data, $orig ) = $r->next_packet ) {
        $s->{packets}++;
        $s->{bytes} += $orig;
        my $p = decode( $lt, $data, $verify );
        $p->{len} = $orig;
        if ( $p->{err} ) {
            $s->{errors}++;
            $eb->{ $p->{err} }++;
            next;
        }
        if    ( $p->{l3} == 4 ) { $s->{ipv4}++ }
        elsif ( $p->{l3} == 6 ) { $s->{ipv6}++ }
        else                    { $s->{non_ip}++ }
        $s->{csum_bad}++ if $p->{csum_bad};
        $s->{frags}++    if $p->{frag};
        if ( $filter && !$filter->($p) ) { $s->{filtered}++; next }
        $s->{matched}++;
        $table->add( $p, $ts ) if $p->{l3};
    }
    $s->{truncated_files}++ if $r->truncated;
    return $r->count;
}

sub finish {
    my $self = shift;
    $self->{table}->flush('eof');
    my $s = $self->{stats};
    $s->{flows}      = $self->{table}->created;
    $s->{peak_flows} = $self->{table}->peak;
    return {
        stats     => $s,
        errors_by => $self->{errors_by},
        flows     => $self->{flows},
    };
}

1;
