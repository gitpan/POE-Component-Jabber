package POE::Filter::Jabber;

use strict;
use Carp;
use XML::Parser;
use Jabber::NodeFactory;

sub new {
    my $class	= shift;
    my %args	= @_;
    my $self	= {};

    $self = {
	parser => new XML::Parser (
	    Handlers => {
		Start	=> sub { $self->_startTag( @_ ) },
		End	=> sub { $self->_endTag( @_ ) },
		Char	=> sub { $self->_charData( @_ ) },
	    }
	)->parse_start(),
	debug	    => $args{'debug'},
	streamid    => undef,
	depth	    => 0,
	currnode    => undef,
	streamerror => undef,
    };


    bless $self, $class;
}

sub debug {
    my $self = shift;

    $self->{'debug'} = $_[0] if @_;
    return( $self->{'debug'} );
}

sub get {
    my( $self, $raw )	= @_;

    foreach my $line ( @$raw ) {
	$self->{'parser'}->parse_more( $line );
    }
    if( $self->{'depth'} == 1) {
	$self->_debug( "get: got " . $self->{'currnode'}->toStr() );
	$self->{'depth'} = 0;
	return( [ [ $self->{'streamid'}, $self->{'currnode'} ] ] );
    } else {
	return [];
    }
}

sub put {
    my( $self, $nodes ) = @_;
    my @output;

    foreach my $node ( @{ $nodes } ) {
	if( ref( $node ) eq 'Jabber::NodeFactory::Node' ) {
	    $self->_debug( "put: sending " . $node->toStr() );
	    push @output, $node->toStr();
	} else {
	    $self->_debug( "put: sending " . $node );
	    push @output, $node;
	}
    }

    return( \@output );
}

sub _startTag {
    my( $self, $expat, $tag, %attr ) = @_;

    if( $tag eq "stream:stream" ) {
	$self->_debug( "_startTag: stream established from $attr{'from'} id $attr{'id'}" );
	$self->{'streamid'} = $attr{'id'};
    } else {
	$self->{'depth'} += 1;

	# Top level fragment
	if( $self->{'depth'} == 1 ) {
	    # Check it's not an error
	    if( $tag eq 'stream:error' ) {
		$self->{'streamerror'} = 1;
	    } else {
		# Not an error = create the node
		$self->_debug( "_startTag: creating new node for $tag" );
		$self->{'currnode'} = Jabber::NodeFactory::Node->new( $tag );
		$self->{'currnode'}->attr( $_, $attr{$_} ) foreach keys %attr;
	    }
	} else {
	    # Some node within a fragment
	    my $kid = $self->{'currnode'}->insertTag( $tag );
	    $kid->attr( $_, $attr{$_} ) foreach keys %attr;
	    $self->{'currnode'} = $kid;
	    $self->_debug( "_startTag: $tag" );
	}
    }
}

sub _endTag {
    my ($self, $expat, $tag ) = @_;

    # Don't bother to do anything if there's an error
    return [] if $self->{'streamerror'};

    if( $self->{'depth'} == 1 ) {
	$self->_debug( "_endTag: node closed with tag $tag" );
	#$self->{'parser'}->parse_done();
    } else {
	$self->_debug( "_endTag: $tag" );
	$self->{'currnode'} = $self->{'currnode'}->parent();
	$self->{'depth'} -= 1;
    }

}

sub _charData {
    my( $self, $expat, $data ) = @_;

    # Die if we get an error mid-stream
    if( $self->{'streamerror'} ) {
	croak "Stream error: $data";
    } else {
	# Otherwise append the data to the current node
	$self->{'currnode'}->data( $self->{'currnode'}->data() . $data );
    }
}

sub _debug {
    my( $self, $string ) = @_;

    if( $self->{'debug'} ) {
	print STDERR "[P:F:J]$string\n";
    }
}

1;
