package POE::Component::Jabber::Client::Component;
use POE::Preprocessor;
const XNode POE::Filter::XML::Node
use warnings;
use strict;

use POE qw/ Wheel::ReadWrite Component::Client::TCP /;
use POE::Component::Jabber::Error;
use POE::Filter::XML;
use POE::Filter::XML::Node;
use POE::Filter::XML::NS qw/ :JABBER :IQ /;
use Digest::SHA1 qw/ sha1_hex /;

our $VERSION = '1.0';

sub new()
{
	my $class = shift;
	my $me = $class . '->new()';
	die "$me requires an even number of arguments" if(@_ & 1);
	
	my $args = {};
	while($#_ != -1)
	{
		my $key = lc(shift(@_));
		my $value = shift(@_);
		if(ref($value) eq 'HASH')
		{
			my $hash = {};
			foreach my $sub_key (keys %$value)
			{
				$hash->{lc($sub_key)} = $value->{$sub_key};
			}
			$args->{$key} = $hash;
			next;
		}
		$args->{$key} = $value;
	}

	$args->{'alias'} = $class unless defined $args->{'alias'};
	$args->{'xmlns'} = +NS_JABBER_ACCEPT;
	$args->{'stream'} = +XMLNS_STREAM unless defined $args->{'stream'};
	$args->{'debug'} = 0 unless defined $args->{'debug'};
	
	die "$me requires PASSWORD to be defined" if not defined
		$args->{'password'};
	die "$me requires InitFinish to be defined" if not defined
		$args->{'states'}->{'initfinish'};
	die "$me requires InputEvent to be defined" if not defined
		$args->{'states'}->{'inputevent'};
	die "$me requires ErrorEvent to be defined" if not defined
		$args->{'states'}->{'errorevent'};

	POE::Component::Client::TCP->new
	(
		SessionParams => 
		[ 
			options => 	
			{ 
				debug => $args->{'debug'}, 
				trace => $args->{'debug'} 
			} 
		],
		
		RemoteAddress => $args->{'ip'},
		RemotePort => $args->{'port'},
		ConnectTimeout => 5,
		
		Filter => 'POE::Filter::XML',

		Connected => \&init_connection,
		Disconnected => \&disconnected,

		ServerInput => \&init_input_handler,
		ServerError => \&server_error,

		InlineStates => {
			output_handler => \&output_handler,
			shutdown_socket => \&shutdown_socket,
			set_auth => \&set_auth,
			return_to_sender => \&return_to_sender,
		},
		
		Alias => $args->{'alias'},
		Started => \&start,
		Args => [ $args ],
	);
}

sub return_to_sender()
{
	my ($kernel, $heap, $session, $event, $node) = 
		@_[KERNEL, HEAP, SENDER, ARG0, ARG1];
	
	++$heap->{'id'};
	$heap->{'PENDING'}->{$heap->{'id'}}->[0] = $session->ID();
	$heap->{'PENDING'}->{$heap->{'id'}}->[1] = $event;
	
	my $attrs = $node->get_attrs();

	if(exists($attrs->{'id'}))
	{
		warn $node->to_str();
		warn "Overwriting pre-existing 'id'!";
	}
	
	$node->attr('id', $heap->{'id'});
	$kernel->yield('output_handler', $node);
}

sub set_auth()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	my $node = XNode->new('handshake');
	$node->data(&sha1_hex($heap->{'sid'}.$heap->{'CONFIG'}->{'password'}));
	$kernel->yield('output_handler', $node);
	return;
}

sub start()
{
	my ($heap, $config) = @_[HEAP, ARG0];
	
	$heap->{'CONFIG'} = $config;
	$heap->{'id'} = 0;
	$heap->{'sid'} = 0;
}

sub init_connection()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	my $cfg  = $heap->{'CONFIG'};

	my $element = XNode->new('stream:stream',
	['to', $cfg->{'hostname'}, 
	'xmlns', $cfg->{'xmlns'},
	'xmlns:stream', $cfg->{'stream'}]
	)->stream_start(1);

	$kernel->yield('output_handler', $element);

	return;
}

sub disconnected()
{
	$_[KERNEL]->post($_[HEAP]->{'CONFIG'}->{'state_parent'},
		$_[HEAP]->{'CONFIG'}->{'states'}->{'errorevent'},
		+PCJ_SOCKDISC);
}

sub shutdown_socket()
{
	my ($kernel, $time) = @_[KERNEL, ARG0];

	$kernel->delay('shutdown', $time);
	return;
}

sub output_handler()
{
	my ($heap, $data) = @_[HEAP, ARG0];

	if ($heap->{'CONFIG'}->{'debug'})
	{
		my $xml;
		if (ref $data eq 'XNode')
		{
			$xml = $data->to_str();
		} else {
			$xml = $data;
		}
		&debug_message( "Sent: $xml" );
	}

	$heap->{'server'}->put($data);
	return;
}

sub input_handler()
{
	my ($kernel, $heap, $node) = @_[KERNEL, HEAP, ARG0];
	my $attrs = $node->get_attrs();

	if ($heap->{'CONFIG'}->{'debug'})
	{
		&debug_message("Recd: ".$node->to_str());
	}

	if(exists($attrs->{'id'}))
	{
		if(defined($heap->{'PENDING'}->{$attrs->{'id'}}))
		{
			my $array = delete $heap->{'PENDING'}->{$attrs->{'id'}};
			$kernel->post($array->[0], $array->[1], $node);
			return;
		}
	}
	
	$kernel->post($heap->{'CONFIG'}->{'state_parent'},
		$heap->{'CONFIG'}->{'states'}->{'inputevent'} , $node);
	return;
}

sub init_input_handler()
{
	my ($kernel, $heap, $node) = @_[KERNEL, HEAP, ARG0];
	
	if($node->name() eq 'handshake')
	{
		$kernel->post($heap->{'CONFIG'}->{'state_parent'},
			$heap->{'CONFIG'}->{'states'}->{'initfinish'});
		$kernel->state('got_server_input', \&input_handler);

	} elsif($node->name() eq 'stream:stream') {
	
		$heap->{'sid'} = $node->attr('id');
		$kernel->yield('set_auth');
	}
}

sub server_error()
{
	my ($kernel, $heap, $call, $code, $err) = @_[KERNEL, HEAP, ARG0..ARG2];
	
	warn "Server Error: $call: $code -> $err\n";
	$kernel->post($heap->{'CONFIG'}->{'state_parent'},
		$heap->{'CONFIG'}->{'states'}->{'errorevent'},
		+PCJ_SOCKFAIL, $call, $code, $err);
}

sub debug_message()
{
	my $msg  = shift;
	print STDERR "\n", scalar (localtime (time)), ": $msg\n";
}

1;

__END__

=pod

=head1 NAME

POE::Component::Jabber::Client::Component - A POE Component for communicating 
over Jabber within the jabberd 1.4.x jabber:component:accept namespace

=head1 SYNOPSIS

 use POE qw/ Component::Jabber::Client::Component Component::Jabber::Error /;
 use POE::Filter::XML::Node;
 use POE::Filter::XML::NS qw/ :JABBER :IQ /;

 POE::Component::Jabber::Client::Component->new(
   IP 		=> 'jabber.server',
   PORT 	=> '5222'
   HOSTNAME	=> 'jabber.server',
   ALIAS	=> 'POCO',
   PASSWORD => 'password'
   STATE_PARENT => 'My_Session',
   STATES => {
	 INITFINISH => 'My_Init_Finished',
	 INPUTEVENT => 'My_Input_Handler',
	 ERROREVENT => 'My_Error_Handler',
   }
 );
 
 $poe_kernel->post('POCO', 'output_handler, $node);
 $poe_kernel->post('POCO', 'return_to_sender', $node);

=head1 DESCRIPTION

This client class provides seemless connection and authentication within the
legacy jabber:component:accept namespace.

=head1 EVENTS AND METHODS

=over 4

=item new()

Accepts many arguments: 

=over 2

=item IP

The IP address in dotted quad, or the FQDN for the server

=item PORT

The remote port of the server to connect.

=item HOSTNAME

The hostname of the server. Used in addressing.

=item PASSWORD

The password to be used in handshake authentication (SHA-1)

=item ALIAS

The alias the component should register for use within POE. Defaults to
the class name.

=item STATE_PARENT

The alias or session id of the session you want the component to contact.

=item STATES

A hashref containing the event names the component should fire upon finishing
initialization and receiving input from the server. 

INITFINISH, INPUTEVENT, and ERROREVENT must be defined.

INITFINISH is fired after connection setup, TLS and SASL negotiation, and 
resource binding and session establishment take place.

ARG0 in INITFINISH will be your jid as a string.
ARG0 in INPUTEVENT will be the payload as a POE::Filter::XML::Node.
ARG0 in ERROREVENT will be a POE::Component::Jabber::Error

See POE::Component::Jabber::Error for possible error types and constants.

See POE::Filter::XML and its accompanying documentation to properly manipulate
incoming data in your INPUTEVENT, and creation of outbound data.

=item DEBUG

If bool true, will enable debugging and tracing within the component. All XML
sent or received through the component will be printed to STDERR

=back

=back

=head1 EVENTS

=over 4

=item 'output_handler'

This is the event that you use to push data over the wire. Accepts either raw
XML or POE::Filter::XML::Nodes.

=item 'return_to_sender'

This event takes (1) a POE::Filter::XML::Node and gives it a unique id, and 
(2) a return event and places it in the state machine. Upon receipt of 
response to the request, the return event is fired with the response packet.

=item 'shutdown_socket'

One argument, time in seconds to call shutdown on the underlying Client::TCP

=back

=head1 AUTHOR

Copyright (c) 2003, 2004 Nicholas Perez. Distributed under the GPL.

=cut

