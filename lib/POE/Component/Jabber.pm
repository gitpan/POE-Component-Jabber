
package POE::Component::Jabber;

use strict;
use Carp;
use POE qw( Wheel::SocketFactory Wheel::ReadWrite Driver::SysRW Filter::Jabber Component::Jabber::Auth );

use Jabber::NS qw( :all );
use Jabber::NodeFactory;
use Socket;
use Digest::SHA1 qw( sha1_hex );

use vars qw( $VERSION );
use constant JABBER_PORT => 5222;

our $VERSION = '0.1';

sub new {
    my( $package, $alias ) = splice @_, 0, 2;

    unless( $alias ) {
	croak "Not enough arguments to POE::Component::Jabber::new()";
    }

    POE::Session->create(
	package_states => [
	    $package => [ qw(
		_start _stop _sock_down _sock_failed _sock_up _parse
		_authfailed _authed 
		connect disconnect register unregister send auth
	    ) ],
	],
	args => [ $alias, @_ ],
    );

    return undef;
}

sub _start {
    my( $kernel, $session, $heap, $alias ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];
    my @options = @_[ ARG1 .. $#_ ];

    $session->option( @options ) if @options;
    $kernel->alias_set( $alias );
}

sub _stop {
    my( $kernel, $heap, $session ) = @_[ KERNEL, HEAP, SESSION ];

    _debug( "_stop: received") if $heap->{'debug'};
    $kernel->call( $session, 'disconnect' );
}

sub connect {
    my( $kernel, $heap, $session, $args ) = @_[ KERNEL, HEAP, SESSION, ARG0 ];

    if( $args ) {
	my %arg;
	if( ref $args eq 'ARRAY' ) {
	    %arg = @$args;
	} elsif( ref $args eq 'HASH' ) {
	    %arg = %$args;
	} else {
	    croak "First argument to connect() should be a hash or array reference";
	}

	$heap->{'host'}	    = $arg{'host'}	|| 'localhost';
	$heap->{'port'}	    = $arg{'port'}	|| JABBER_PORT;
	$heap->{'user'}	    = $arg{'user'}	if exists $arg{'user'};
	$heap->{'password'} = $arg{'password'}	if exists $arg{'password'};
	$heap->{'resource'} = $arg{'resource'}	if exists $arg{'resource'};
	$heap->{'secret'}   = $arg{'secret'}	|| 'undef';
	$heap->{'type'}	    = $arg{'type'}	|| NS_CLIENT;
	$heap->{'nf'}	    = Jabber::NodeFactory->new();
	$heap->{'debug'}    = $arg{'debug'};
    }

    # Disconnect if we're already logged into a server
    $kernel->call( $session, 'disconnect' );

    _debug( "connect: Connecting to $heap->{'host'}:$heap->{'port'}" )
      if $heap->{'debug'};

    $heap->{'socketfactory'} =
	POE::Wheel::SocketFactory->new(
	    SocketDomain    => AF_INET,
	    SocketType	    => SOCK_STREAM,
	    SocketProtocol  => 'tcp',
	    RemoteAddress   => $heap->{'host'},
	    RemotePort	    => $heap->{'port'},
	    SuccessEvent    => '_sock_up',
	    FailureEvent    => '_sock_failed',
	);
}

sub disconnect {
    my( $kernel, $heap, $session ) = @_[ KERNEL, HEAP, SESSION ];

    if( $heap->{'socket'} ) {
	_debug( "disconnect: Connection to $heap->{'host'}:$heap->{'port'} shutting down") if $heap->{'debug'};

	$heap->{'socket'}->put( qq[</stream:stream>] );

	# Destory RW wheel for the socket.
	delete $heap->{'socket'};
    
	if( $heap->{'connected'} ) {
	    $heap->{'connected'} = 0;

	    foreach( keys %{ $heap->{'sessions'} } ) {
		# Post this event to all registered sessions
		$kernel->post( $heap->{'sessions'}->{$_}->{'ref'}, 'jabber_disconnected', $heap->{'host'} );
	    }
	}
    }
}

sub _sock_down {
    my( $kernel, $heap ) = @_[ KERNEL, HEAP ];

    _debug( "_sock_down: Connection to $heap->{'host'}:$heap->{'port'} down" ) if $heap->{'debug'};

    $kernel->yield( 'disconnect' );
}

sub _sock_failed {
    my( $kernel, $heap ) = @_[ KERNEL, HEAP ];

    _debug( "_sock_failed: Connection to $heap->{'host'}:$heap->{'port'} failed - $!" ) if $heap->{'debug'};

    _send_event( $kernel, $heap, 'jabber_socketerr', $! );
}

sub _sock_up {
    my( $kernel, $heap, $session, $socket ) = @_[ KERNEL, HEAP, SESSION, ARG0 ];

    _debug( "_sock_up: Connection established to $heap->{'host'}:$heap->{'port'}" ) if $heap->{'debug'};

    # We no longer need the SocketFactory wheel. Scrap it.
    delete $heap->{'socketfactory'};

    # Create a new ReadWrite wheel for the connected socket.
    $heap->{'socket'} = new POE::Wheel::ReadWrite(
	Handle	    => $socket,
	Driver	    => POE::Driver::SysRW->new(),
	Filter	    => POE::Filter::Jabber->new( debug => $heap->{'debug'} ),
	InputEvent  => '_parse',
	ErrorEvent  => '_sock_down',
    );

    if( $heap->{'socket'} ) {
	# Open the stream
	$heap->{'socket'}->put( qq[<?xml version='1.0'?><stream:stream xmlns='$heap->{'type'}' xmlns:stream='http://etherx.jabber.org/streams' to='$heap->{'host'}'>] );
    
	$heap->{'connected'} = 1;
	foreach( keys %{ $heap->{'sessions'} } ) {
	    # Post this event to all registered sessions
	    $kernel->post( $heap->{'sessions'}->{$_}->{'ref'}, 'jabber_connected', $heap->{'host'} );
	}

	# A send auth
	$kernel->yield( 'auth' );
    } else {
	_send_event( $kernel, $heap, 'jabber_socketerr', "Couldn't create ReadWrite wheel for Jabber socket" );
    }
}

sub _parse {
    my( $kernel, $session, $heap, $data ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];

    $heap->{'streamid'} = $data->[0];
    _send_event( $kernel, $heap, 'jabber_' . $data->[1]->name, $data->[1] );
}

sub register {
    my( $heap, $sender, @events ) = @_[ HEAP, SENDER, ARG0 .. $#_ ];

    croak "Not enough arguments" unless @events;

    foreach( @events ) {
	$_ = "jabber_" . $_ unless /^_/;
	$heap->{'events'}->{$_}->{$sender} = $sender;
	$heap->{'sessions'}->{$sender}->{'ref'} = $sender;
	$heap->{'sessions'}->{$sender}->{'refcnt'}++;

	_debug( "register: registered $sender for $_" ) if $heap->{'debug'};
    }
}

sub unregister {
    my( $heap, $sender, @events ) = @_[ HEAP, SENDER, ARG0 .. $#_ ];

    croak "Not enough arguments" unless @events;

    foreach( @events ) {
	delete $heap->{'events'}->{$_}->{$sender};
	$heap->{'sessions'}->{$sender}->{'refcnt'}--;
	delete $heap->{'sessions'}->{$sender} if $heap->{'sessions'}->{$sender}->{'refcnt'} <= 0;

	_debug( "unregister: unregistered $sender for $_" ) if $heap->{'debug'};
    }
}

# Send an event to all registered sessions
# This is an internal sub rather than an event itself
sub _send_event {
    my( $kernel, $heap, $event, @args ) = @_;

    _debug( "_send_event: $event @args" ) if $heap->{'debug'};

    foreach( values %{ $heap->{'events'}->{'jabber_all'} },
	     values %{ $heap->{'events'}->{$event} } ) {
	_debug( "_send_event: sending $event to $_" ) if $heap->{'debug'};
	$kernel->post( $_, $event, @args );
    }
}


sub send {
    my( $kernel, $session, $heap, $node ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];

    if( $heap->{'connected'} ) {
	if( ref( $node ) eq 'Jabber::NodeFactory::Node' ) {
	    $heap->{'socket'}->put($node);
	}
    } else {
	carp "Unable to send node - not connected to server";
    }
}

sub auth {
    my( $kernel, $session, $heap, %args ) = @_[ KERNEL, SESSION, HEAP, ARG0 .. $#_ ];

    $heap->{'user'}	= $args{'user'}	    || $heap->{'user'}	    || 'undef';
    $heap->{'password'}	= $args{'password'} || $heap->{'password'}  || 'undef';
    $heap->{'resource'}	= $args{'resource'} || $heap->{'resource'}  || 'undef';

    POE::Component::Jabber::Auth->new(
	session	    => $session,
	type	    => $heap->{'type'},
	user	    => $heap->{'user'},
	password    => $heap->{'password'},
	resource    => $heap->{'resource'},
	debug	    => $heap->{'debug'},
    );
}

sub _authfailed {
    my( $kernel, $session, $heap, $auth_session ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];

    _send_event( $kernel, $heap, 'jabber_authfailed', $auth_session );
}

sub _authed {
    my( $kernel, $session, $heap, $auth_session ) = @_[ KERNEL, SESSION, HEAP, ARG0 ];

    _send_event( $kernel, $heap, 'jabber_authed', $auth_session );
}

sub _debug {
    my $string = shift;

    print STDERR "[P:C:J]$string\n";
}

1;
__END__
=head1 NAME

POE::Component::Jabber - POE component for accessing Jabber servers

=head1 SYNOPSIS

  use POE::Component::Jabber;

  POE::Component::Jabber->new( 'my client' );

  $kernel->post( 'my client', 'register', qw( authed authfailed ) );
  $kernel->post( 'my client', 'connect', {
                host	    => 'localhost',
                user        => 'test',
                resource    => 'poe',
                password    => 'test',
                debug	    => 1,
  } );


=head1 DESCRIPTION

POE::Component::Jabber is heavily based on POE::Component::IRC and
uses much the same event model. Authentication routines are inspired
by Jabber::Connection.

POE::Filter::Jabber is provided which requires XML::Parser and
sends and receives data as Jabber::NodeFactory::Node objects.

POE::Component::Jabber::Auth implements authentication with the
jabber server. This would be a good module to look at as it
does it in much the way an application would interface with
POE::Component::Jabber by registering for the IQ event.

=head2 METHODS

=over

=item new

  POE::Component::Jabber->new( 'my client' );

Takes one argument which will be the alias for the component.

=back

=head1 EVENTS

These are the events you can call on the component.

=over

=item connect

  $kernel->post( 'my client', 'connect', {
                host	    => 'localhost',
                user        => 'test',
                resource    => 'poe',
                password    => 'test',
                debug	    => 1,
  } );

Connects to the Jabber server. Will trigger a jabber_connected on
successful connection, or jabber_socketerr on failure.  After
successful authentication, a jabber_authed event is triggered.  If
authentication fails, a jabber_authfailed is triggered.

=item disconnect

  $kernel->post( 'my client', 'disconnect' );

Disconnects from the jabber server, will generate a jabber_disconnected
event when complete.

=item register

  $kernel->post( 'my client', 'register', qw( authed authfailed ) );

Registers your session for a list of events.

=item unregister

  $kernel->post( 'my client', 'unregister', qw( authed authfailed ) );

De-registers your session for a list of events.

=item send

  $kernel->post( 'my client', 'send', $node );

Send a Jabber::NodeFactory::Node object to the jabber server.

=item auth

  $kernel->post( 'my client', 'auth', {
                type      => NS_CLIENT,
		user      => 'test',
		password  => 'password',
		resource  => 'resource',
		debug     => 1,
  } );

Authenticate with the jabber server. Will send a jabber_authed or
jabber_authfailed event.

=head1 BUGS

Bound to be loads, this is an early release. Also documentation sucks,
will be improved when I have time.

=head1 AUTHOR

Original Code: Mark Cheverton, <ennui@morat.net>
Maintained by: Mark A. Hershberger, <mah@everybody.org>

=head1 SEE ALSO

Jabber::Connection,
POE::Component::IRC

=cut
`
