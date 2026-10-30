package PcapFlow::Filter;

# Compiler for a subset of the tcpdump/BPF filter language.
#
# The expression is parsed by recursive descent into Perl source, which is
# then compiled once with eval into a single closure. Literals never get
# pasted into the source: addresses and masks live in a constant array and
# are referenced by index, and numbers are validated before use.
#
# Grammar:
#   expr    := and_expr { ('or' | '||') and_expr }
#   and_expr:= unary    { ('and' | '&&') unary }
#   unary   := ('not' | '!') unary | '(' expr ')' | prim
#   prim    := 'ip' | 'ip6' | 'tcp' | 'udp' | 'icmp' | 'icmp6' | 'frag'
#            | 'proto' NUM | 'vlan' [NUM] | 'greater' NUM | 'less' NUM
#            | [dir] 'host' ADDR | [dir] 'net' CIDR | [dir] 'port' NUM
#            | [dir] 'portrange' NUM-NUM
#   dir     := 'src' | 'dst'

use strict;
use warnings;
use Carp qw(croak);
use PcapFlow::Decode qw(str_to_addr);

sub new {
    my ( $class, $text ) = @_;
    my $self = bless { text => $text, consts => [] }, $class;
    $self->{tokens} = [ _tokenize($text) ];
    $self->{pos}    = 0;
    croak "filter: empty expression" unless @{ $self->{tokens} };
    my $src = $self->_expr;
    if ( $self->{pos} < @{ $self->{tokens} } ) {
        $self->_fail("unexpected '$self->{tokens}[$self->{pos}]'");
    }
    $self->{source} = $src;
    $self->{code}   = _compile( $src, $self->{consts} );
    return $self;
}

sub source { $_[0]{source} }
sub code   { $_[0]{code} }
sub match  { $_[0]{code}->( $_[1] ) }

sub _compile {
    my ( $src, $consts ) = @_;
    my @C    = @$consts;
    my $code = eval "sub { my \$p = \$_[0]; ($src) ? 1 : 0 }";    ## no critic
    croak "filter: internal compile error: $@" unless $code;
    return $code;
}

sub _tokenize {
    my $t = shift;
    my @tok;
    while ( $t =~ /\G\s*(\(|\)|&&|\|\||!|[^\s()!]+)/gc ) { push @tok, $1 }
    $t =~ /\G\s*/gc;
    croak "filter: cannot tokenize near '" . substr( $t, pos($t) // 0 ) . "'"
      if ( pos($t) // 0 ) < length $t;
    return @tok;
}

sub _peek { $_[0]{tokens}[ $_[0]{pos} ] }
sub _next { $_[0]{tokens}[ $_[0]{pos}++ ] }

sub _fail {
    my ( $self, $msg ) = @_;
    croak "filter: $msg (token " . ( $self->{pos} + 1 ) . " in '$self->{text}')";
}

sub _expect_num {
    my ( $self, $what, $max ) = @_;
    my $t = $self->_next;
    $self->_fail("expected $what") unless defined $t && $t =~ /^\d+$/;
    $self->_fail("$what $t out of range") if $t > $max;
    return $t + 0;
}

sub _const {
    my ( $self, $v ) = @_;
    push @{ $self->{consts} }, $v;
    return '$C[' . $#{ $self->{consts} } . ']';
}

sub _expr {
    my $self = shift;
    my @parts = ( $self->_and );
    while ( defined( my $t = $self->_peek ) ) {
        last unless $t eq 'or' || $t eq '||';
        $self->{pos}++;
        push @parts, $self->_and;
    }
    return @parts == 1 ? $parts[0] : '(' . join( ' || ', @parts ) . ')';
}

sub _and {
    my $self = shift;
    my @parts = ( $self->_unary );
    while ( defined( my $t = $self->_peek ) ) {
        last unless $t eq 'and' || $t eq '&&';
        $self->{pos}++;
        push @parts, $self->_unary;
    }
    return @parts == 1 ? $parts[0] : '(' . join( ' && ', @parts ) . ')';
}

sub _unary {
    my $self = shift;
    my $t    = $self->_peek;
    $self->_fail('unexpected end of expression') unless defined $t;
    if ( $t eq 'not' || $t eq '!' ) {
        $self->{pos}++;
        return '!' . $self->_unary;
    }
    if ( $t eq '(' ) {
        $self->{pos}++;
        my $e = $self->_expr;
        my $c = $self->_next;
        $self->_fail("expected ')'") unless defined $c && $c eq ')';
        return "($e)";
    }
    return $self->_prim;
}

my %SIMPLE = (
    ip    => '($p->{l3} == 4)',
    ip6   => '($p->{l3} == 6)',
    tcp   => '($p->{l3} && $p->{proto} == 6)',
    udp   => '($p->{l3} && $p->{proto} == 17)',
    icmp  => '($p->{l3} == 4 && $p->{proto} == 1)',
    icmp6 => '($p->{l3} == 6 && $p->{proto} == 58)',
    frag  => '($p->{frag})',
);

# tcpdump's port primitives only match TCP, UDP and SCTP
my %PORT_FIELD = ( src => 'sport', dst => 'dport' );
my $PORT_PROTO = '($p->{l3} && ($p->{proto} == 6 || $p->{proto} == 17 || $p->{proto} == 132))';

sub _prim {
    my $self = shift;
    my $t    = $self->_next;

    return $SIMPLE{$t} if exists $SIMPLE{$t};

    if ( $t eq 'proto' ) {
        my $n = $self->_expect_num( 'protocol number', 255 );
        return "(\$p->{l3} && \$p->{proto} == $n)";
    }
    if ( $t eq 'vlan' ) {
        my $n = $self->_peek;
        if ( defined $n && $n =~ /^\d+$/ ) {
            $n = $self->_expect_num( 'vlan id', 4095 );
            return "(defined \$p->{vlan} && \$p->{vlan} == $n)";
        }
        return '(defined $p->{vlan})';
    }
    if ( $t eq 'greater' ) {
        my $n = $self->_expect_num( 'length', 0xffffffff );
        return "(\$p->{len} >= $n)";
    }
    if ( $t eq 'less' ) {
        my $n = $self->_expect_num( 'length', 0xffffffff );
        return "(\$p->{len} <= $n)";
    }

    my $dir = '';
    if ( $t eq 'src' || $t eq 'dst' ) {
        $dir = $t;
        $t   = $self->_next;
        $self->_fail("expected host, net, port or portrange after '$dir'")
          unless defined $t;
    }
    my @fields = $dir ? ($dir) : qw(src dst);

    if ( $t eq 'host' ) {
        my $s = $self->_next;
        my $a = defined $s ? str_to_addr($s) : undef;
        $self->_fail( 'expected IP address after host' ) unless defined $a;
        my $c = $self->_const($a);
        return _any( map { "\$p->{$_} eq $c" } @fields );
    }
    if ( $t eq 'net' ) {
        my $s = $self->_next;
        $self->_fail('expected address/prefix after net')
          unless defined $s && $s =~ m{^([^/]+)/(\d+)$};
        my ( $addr, $bits ) = ( str_to_addr($1), $2 );
        $self->_fail("bad network '$s'") unless defined $addr;
        my $alen = length $addr;
        $self->_fail("prefix length /$bits too long") if $bits > $alen * 8;
        my $mask = pack "B*", ( '1' x $bits ) . ( '0' x ( $alen * 8 - $bits ) );
        my $net  = $addr & $mask;
        my ( $cm, $cn ) = ( $self->_const($mask), $self->_const($net) );
        return _any( map { "(length(\$p->{$_}) == $alen && (\$p->{$_} & $cm) eq $cn)" } @fields );
    }
    if ( $t eq 'port' ) {
        my $n = $self->_expect_num( 'port number', 65535 );
        return "($PORT_PROTO && " . _any( map { "\$p->{$PORT_FIELD{$_}} == $n" } @fields ) . ')';
    }
    if ( $t eq 'portrange' ) {
        my $r = $self->_next;
        $self->_fail('expected N-M after portrange')
          unless defined $r && $r =~ /^(\d+)-(\d+)$/;
        my ( $lo, $hi ) = ( $1 + 0, $2 + 0 );
        $self->_fail("bad portrange $r") if $lo > $hi || $hi > 65535;
        return "($PORT_PROTO && "
          . _any( map { "(\$p->{$PORT_FIELD{$_}} >= $lo && \$p->{$PORT_FIELD{$_}} <= $hi)" } @fields ) . ')';
    }
    $self->{pos}--;
    $self->_fail("unknown primitive '$t'");
}

sub _any { @_ == 1 ? "($_[0])" : '(' . join( ' || ', @_ ) . ')' }

1;
