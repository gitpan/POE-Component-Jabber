package POE::Component::Jabber::Auth;

use strict;
use Carp;
use POE;
use Jabber::NS qw( :all );
use Jabber::NodeFactory;
use Digest::SHA1 qw( sha1_hex );

sub new {
    my $package	= shift;
    my %args    = @_;


    POE::Session->create(
	package_states => [
	    $package => [ qw(
		_start _stop _check
		jabber_iq
	    ) ],
	],
	heap => {
	    session	=> $args{'session'},
	    type	=> $args{'type'},
	    user	=> $args{'user'},
	    password	=> $args{'password'},
	    resource	=> $args{'resource'},
	    nf		=> Jabber::NodeFactory->new(),
	    debug	=> $args{'debug'},
	    secret	=> $args{'secret'},
	},
    );

    return undef;
}

sub _start {
    my( $kernel, $session, $heap ) = @_[ KERNEL, SESSION, HEAP ];
    my $streamid;

    if( $heap->{'type'} eq NS_CLIENT ) {

	# Ask the server what auth methods are available
	my $auth_node = $heap->{'nf'}->newNode( 'iq' );
	$auth_node->attr( 'type', IQ_GET );
	$auth_node->attr( 'id', $session->ID() . ':1' );

	my $query = $auth_node->insertTag( 'query' );
	$query->attr( 'xmlns', NS_AUTH );
	$query->insertTag( 'username' )->data( $heap->{'user'} );

	_debug( "_start: sending auth request" ) if $heap->{'debug'};
	$kernel->post( $heap->{'session'}, 'register', qw( iq ) );
	$kernel->post( $heap->{'session'}, 'send', $auth_node );

	# Set a delayed method to check if we have authd and keep session alive
	$heap->{'retry'} = 1;
	$kernel->delay( '_check', 1 );
    } elsif( $heap->{'type'} eq NS_ACCEPT ) {
	my $handshake = $heap->{'nf'}->newNode( 'handshake' );
	$handshake->data( sha1_hex( $streamid . $heap->{'secret'} ) );

	$kernel->post( $heap->{'session'}, 'send', $handshake );
    }
}

sub _stop {
    my( $kernel, $session, $heap ) = @_[ KERNEL, SESSION, HEAP ];

    $kernel->post( $heap->{'session'}, 'unregister', qw( iq ) );
    _debug( "_stop: received") if $heap->{'debug'};
}

sub _check {
    my( $kernel, $session, $heap ) = @_[ KERNEL, SESSION, HEAP ];

    if( $heap->{'retry'} ) {
	_debug( "_check: Not reponse received after $heap->{'retry'} seconds") if $heap->{'debug'};
	if( $heap->{'retry'} > 10 ) {
	    _debug( "_check: No response, auth failed") if $heap->{'debug'};
	} else {
	    $heap->{'retry'}++;
	    $kernel->delay( '_check', 1 );
	}
    }
}

sub jabber_iq {
    my( $kernel, $session, $heap, $node ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];
    my $streamid;

    _debug( "jabber_iq: received " . $node->toStr) if $heap->{'debug'};

    if( $node->attr( 'id' ) eq $session->ID . ':1' ) {
	# We have the result of the auth method query
	if( $node->attr( 'type' ) eq IQ_ERROR ) {
	    _debug( "jabber_iq: received error from iq auth method query" ) if $heap->{'debug'};
	    $heap->{'retry'} = 0;
	    $kernel->post( $heap->{'session'}, '_authfailed', $session->ID() );
	} elsif( $node->attr( 'type' ) eq IQ_RESULT ) {
	    if( $node->getTag( 'query', NS_AUTH ) ) {
		_debug( "jabber_iq: received NS_AUTH iq query" ) if $heap->{'debug'};

		my $auth_node = $heap->{'nf'}->newNode( 'iq' );
		$auth_node->attr( 'type', IQ_SET );
		$auth_node->attr( 'id', $session->ID . ':2' );

		my $query = $auth_node->insertTag( 'query' );
		$query->attr( 'xmlns', NS_AUTH );
		$query->insertTag( 'username' )->data( $heap->{'user'} );
		$query->insertTag( 'resource' )->data( $heap->{'resource'} );

		if( $node->getTag( 'query' )->getTag( 'token' ) ) {
		    _debug( "jabber_iq: zerok auth supported" ) if $heap->{'debug'};

		    my $hash	= sha1_hex( $heap->{'password'} );
		    my $seq	= $node->getTag( 'query' )->getTag( 'sequence' )->data;
		    $hash	= sha1_hex( $hash . $node->getTag( 'query' )->getTag( 'token' )->data );
		    $hash	= sha1_hex( $hash ) while $seq--;
		    $query->insertTag( 'hash' )->data( $hash );
		} elsif ( $node->getTag( 'query' )->getTag( 'digest' ) ) {
		    _debug( "jabber_iq: digest auth supported" ) if $heap->{'debug'};

		    $query->insertTag( 'digest' )->data( sha1_hex( $streamid . $heap->{'password'} ) );
		} elsif ( $node->getTag( 'query' )->getTag( 'password' ) ) {
		    _debug( "jabber_iq: plaintext auth supported" ) if $heap->{'debug'};

		    $query->insertTag( 'password' )->data( $heap->{'password'} );
		} else {
		    croak "No authentication methods available";
		}

		$heap->{'retry'} = 1;
		$kernel->post( $heap->{'session'}, 'send', $auth_node );
	    }
	}
    } elsif( $node->attr( 'id' ) eq $session->ID . ':2' ) {
	if( $node->attr( 'type' ) eq IQ_ERROR ) {
	    _debug( "jabber_iq: received error from iq auth" ) if $heap->{'debug'};
	    $heap->{'retry'} = 0;
	    $kernel->post( $heap->{'session'}, '_authfailed', $session->ID() );
	} else {
	    _debug( "jabber_iq: successfully authed" ) if $heap->{'debug'};
	    $heap->{'retry'} = 0;
	    $kernel->post( $heap->{'session'}, '_authed', $session->ID() );
	}
    }
}

sub _debug {
    my $string = shift;

    print STDERR "[P:C:J:A]$string\n";
}

1;
