package PcapFlow::Parallel;

# Process several capture files at once with fork(2).
#
# One child per file (at most `jobs` alive at a time). Each child runs its
# own Analyzer and streams finished flow records back over a pipe(2) as
# tab-separated lines. The parent multiplexes the pipes with select(2), so
# a chatty child never blocks on a full pipe while the parent waits on
# another one, reaps children with waitpid(2), and checks exit statuses.
# SIGINT/SIGTERM in the parent are forwarded to the children.
#
# Files are assumed to be consecutive pieces of one capture (tcpdump -C/-G
# rotation). A flow cut by a file boundary comes back as an 'eof' record
# from one child and a continuation from the next; merge() stitches them
# using the same idle/close timeout rules as the serial flow table.

use strict;
use warnings;
use Carp qw(croak);
use IO::Select;
use POSIX ();
use PcapFlow::Analyzer;

my @FIELDS = qw(proto src sport dst dport first last pkts_fwd pkts_rev
  bytes_fwd bytes_rev tcp_flags rtt vlan closed first_syn end);
my %NUMERIC = map { $_ => 1 } qw(proto sport dport first last pkts_fwd
  pkts_rev bytes_fwd bytes_rev closed first_syn);
my %FLOAT = map { $_ => 1 } qw(first last rtt);

sub _encode_flow {
    my $f = shift;
    return join( "\t", 'F', map {
        my $v = $f->{$_};
        !defined $v ? '-' : $FLOAT{$_} ? sprintf( '%.17g', $v ) : $v
    } @FIELDS ) . "\n";
}

sub _decode_flow {
    my @v = @_;
    my %f;
    @f{@FIELDS} = @v;
    for ( keys %f ) {
        if    ( $f{$_} eq '-' && !$NUMERIC{$_} ) { $f{$_} = undef }
        elsif ( $NUMERIC{$_} || $FLOAT{$_} )     { $f{$_} += 0 }
    }
    $f{tcp_flags} //= '';
    return \%f;
}

sub run {
    my (%o) = @_;
    my @files = @{ $o{files} };
    my $jobs  = $o{jobs} || 1;
    my %aopt  = map { $_ => $o{$_} } grep { exists $o{$_} }
      qw(filter idle_timeout close_timeout verify_checksums);
    # compile the filter once in the parent so syntax errors surface early
    PcapFlow::Filter->new( $aopt{filter} ) if defined $aopt{filter} && length $aopt{filter};

    my @results;
    my %live;    # pid => state
    my $sel   = IO::Select->new;
    my $next  = 0;
    my $error;

    my $kill_all = sub {
        my $sig = shift;
        kill $sig, keys %live if %live;
        waitpid $_, 0 for keys %live;
        %live = ();
    };
    local $SIG{INT}  = sub { $kill_all->('TERM'); die "interrupted\n" };
    local $SIG{TERM} = sub { $kill_all->('TERM'); die "terminated\n" };
    local $SIG{PIPE} = 'IGNORE';

    while ( ( $next < @files && !$error ) || %live ) {
        while ( !$error && $next < @files && keys(%live) < $jobs ) {
            my $st = _spawn( $files[$next], $next, \%aopt );
            $live{ $st->{pid} } = $st;
            $sel->add( $st->{fh} );
            $next++;
        }
        my @ready = $sel->can_read;
        for my $fh (@ready) {
            my ($st) = grep { $_->{fh} == $fh } values %live;
            next unless $st;
            my $n = sysread $fh, $st->{buf}, 65536, length $st->{buf};
            if ( !defined $n ) {
                next if $!{EINTR} || $!{EAGAIN};
                croak "read from worker $st->{pid}: $!";
            }
            if ($n) {
                my @lines = split /\n/, $st->{buf}, -1;
                $st->{buf} = pop @lines;
                _consume( $st, $_ ) for @lines;
                next;
            }
            # EOF: reap the child and check how it ended
            $sel->remove($fh);
            close $fh;
            waitpid $st->{pid}, 0;
            my $status = $?;
            delete $live{ $st->{pid} };
            if ( defined $st->{err} ) {
                $error //= "$st->{file}: $st->{err}";
            }
            elsif ( $status != 0 ) {
                $error //= sprintf '%s: worker exited with status %d signal %d',
                  $st->{file}, $status >> 8, $status & 127;
            }
            $results[ $st->{idx} ] = $st->{res};
            $kill_all->('TERM') if $error;
        }
    }
    croak $error if $error;
    return combine( \@results, %aopt );
}

sub _spawn {
    my ( $file, $idx, $aopt ) = @_;
    pipe( my $r, my $w ) or croak "pipe: $!";
    my $pid = fork;
    croak "fork: $!" unless defined $pid;
    if ( $pid == 0 ) {
        close $r;
        $SIG{INT} = $SIG{TERM} = 'DEFAULT';
        binmode $w;
        my $ok = eval {
            my $an = PcapFlow::Analyzer->new(
                %$aopt, on_flow => sub { print {$w} _encode_flow( $_[0] ) } );
            $an->process($file);
            my $res = $an->finish;
            my $s   = $res->{stats};
            print {$w} "S\t$_\t$s->{$_}\n" for sort keys %$s;
            print {$w} "X\t$_\t$res->{errors_by}{$_}\n" for sort keys %{ $res->{errors_by} };
            1;
        };
        if ( !$ok ) {
            ( my $e = $@ ) =~ s/\s+/ /g;
            $e =~ s/ at \S+ line \d+\.? ?$//;
            print {$w} "E\t$e\n";
        }
        close $w;
        # _exit: skip END blocks and destructors inherited from the parent
        POSIX::_exit( $ok ? 0 : 3 );
    }
    close $w;
    return {
        pid  => $pid,
        fh   => $r,
        file => $file,
        idx  => $idx,
        buf  => '',
        res  => { flows => [], stats => {}, errors_by => {} },
    };
}

sub _consume {
    my ( $st, $line ) = @_;
    my ( $tag, @v ) = split /\t/, $line, -1;
    if    ( $tag eq 'F' ) { push @{ $st->{res}{flows} }, _decode_flow(@v) }
    elsif ( $tag eq 'S' ) { $st->{res}{stats}{ $v[0] } = $v[1] }
    elsif ( $tag eq 'X' ) { $st->{res}{errors_by}{ $v[0] } = $v[1] }
    elsif ( $tag eq 'E' ) { $st->{err} = $v[0] }
    return;
}

# Combine per-file results (in file order) into one result.
sub combine {
    my ( $results, %o ) = @_;
    my ( %stats, %errs, @flows );
    for my $r (@$results) {
        for my $k ( keys %{ $r->{stats} } ) {
            if ( $k eq 'peak_flows' ) {
                $stats{$k} = $r->{stats}{$k} if $r->{stats}{$k} > ( $stats{$k} // 0 );
            }
            else { $stats{$k} += $r->{stats}{$k} }
        }
        $errs{$_} += $r->{errors_by}{$_} for keys %{ $r->{errors_by} };
        push @flows, @{ $r->{flows} };
    }
    my $merged = merge( \@flows, %o );
    $stats{flows} = scalar @$merged;
    return { stats => \%stats, errors_by => \%errs, flows => $merged };
}

my @FLAG_ORDER = qw(F S R P A U E C);

sub _endpoint { "$_[0]{$_[1]}|" . $_[0]{ $_[1] eq 'src' ? 'sport' : 'dport' } }

sub _canon_key {
    my $f = shift;
    my ( $x, $y ) = ( _endpoint( $f, 'src' ), _endpoint( $f, 'dst' ) );
    return join '/', $f->{proto}, $x lt $y ? ( $x, $y ) : ( $y, $x );
}

# Stitch flow fragments that were split only because the capture was split.
sub merge {
    my ( $flows, %o ) = @_;
    my $idle  = $o{idle_timeout}  // 60;
    my $close = $o{close_timeout} // 5;
    $close = $idle if $close > $idle;
    my %by;
    push @{ $by{ _canon_key($_) } }, $_ for @$flows;

    my @out;
    for my $k ( keys %by ) {
        my @list = sort { $a->{first} <=> $b->{first} } @{ $by{$k} };
        my $prev = shift @list;
        for my $cur (@list) {
            my $gap = $cur->{first} - $prev->{last};
            my $ok  = $prev->{end} eq 'eof'
              && $gap < ( $prev->{closed} ? $close : $idle )
              && !( $prev->{closed} && $cur->{first_syn} && $cur->{proto} == 6 );
            if ( !$ok ) { push @out, $prev; $prev = $cur; next }
            _absorb( $prev, $cur );
        }
        push @out, $prev;
    }
    @out = sort {
        $a->{first} <=> $b->{first} || $a->{src} cmp $b->{src}
          || $a->{sport} <=> $b->{sport}
    } @out;
    return \@out;
}

sub _absorb {
    my ( $p, $c ) = @_;
    my $same = $c->{src} eq $p->{src} && $c->{sport} == $p->{sport}
      && $c->{dst} eq $p->{dst} && $c->{dport} == $p->{dport};
    my ( $pf, $pr, $bf, $br ) = $same
      ? @$c{qw(pkts_fwd pkts_rev bytes_fwd bytes_rev)}
      : @$c{qw(pkts_rev pkts_fwd bytes_rev bytes_fwd)};
    $p->{pkts_fwd}  += $pf;
    $p->{pkts_rev}  += $pr;
    $p->{bytes_fwd} += $bf;
    $p->{bytes_rev} += $br;
    $p->{last} = $c->{last} if $c->{last} > $p->{last};
    my %fl = map { $_ => 1 } split //, $p->{tcp_flags} . $c->{tcp_flags};
    $p->{tcp_flags} = join '', grep { $fl{$_} } @FLAG_ORDER;
    $p->{rtt}    //= $c->{rtt};
    $p->{closed} ||= $c->{closed};
    $p->{end} = $c->{end};
    return;
}

1;
