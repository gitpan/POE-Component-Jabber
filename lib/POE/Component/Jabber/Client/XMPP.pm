package POE::Component::Jabber::Client::XMPP;
use POE::Preprocessor;
const XNode POE::Filter::XML::Node
use warnings;
use strict;

use POE qw/ Wheel::ReadWrite Component::Client::TCP /;
use POE::Component::Jabber::Client::XMPP::TLS;
use POE::Component::Jabber::Error;
use POE::Filter::XML;
use POE::Filter::XML::Node;
use POE::Filter::XML::NS qw/ :JABBER :IQ /;
use Digest::MD5 qw/ md5_hex /;
use MIME::Base64;
use Authen::SASL;
use Symbol qw(gensym);

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
	$args->{'xmlns'} = +NS_JABBER_CLIENT;
	$args->{'stream'} = +XMLNS_STREAM unless defined $args->{'stream'};
	$args->{'debug'} = 0 unless defined $args->{'debug'};
	$args->{'version'} = '1.0' unless defined $args->{'version'};
	$args->{'resource'} = &md5_hex(time().rand().$$.rand().$^T.rand()) 
		unless defined $args->{'resource'};
	
	die "$me requires username to be defined" if not defined
		$args->{'username'};
	die "$me requires password to be defined" if not defined
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
			initiate_stream => \&initiate_stream,
			output_handler => \&output_handler,
			challenge_response => \&challenge_response,
			shutdown_socket => \&shutdown_socket,
			set_auth => \&set_auth,
			return_to_sender => \&return_to_sender,
			build_tls_wheel => \&build_tls_wheel,
			binding => \&binding,
			session_establish => \&session_establish,
			
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
	my ($kernel, $heap, $mech) = @_[KERNEL, HEAP, ARG0];

	my $sasl = Authen::SASL->new(
		mechanism => 'DIGEST_MD5',
		callback  => {
			user => $heap->{'CONFIG'}->{'username'},
			pass => $heap->{'CONFIG'}->{'password'},
		}
	);

	$heap->{'challenge'} = $sasl;

	my $node = XNode->new('auth',
	['xmlns', +NS_XMPP_SASL, 'mechanism', $mech]);

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
	my ($kernel, $heap, $socket) = @_[KERNEL, HEAP, ARG0];

	$heap->{'socket'} = $socket;

	$kernel->yield('initiate_stream');

	return;
}

sub initiate_stream()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	my $cfg = $heap->{'CONFIG'};

	my $element = XNode->new('stream:stream',
	['to', $cfg->{'hostname'}, 
	'xmlns', $cfg->{'xmlns'}, 
	'xmlns:stream', $cfg->{'stream'}, 
	'version', $cfg->{'version'}]
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

sub challenge_response()
{
	my ($kernel, $heap, $node) = @_[KERNEL, HEAP, ARG0];

	if ($heap->{'CONFIG'}->{'debug'}) {
		&debug_message(
			"Server sent a challenge.  Decoded Challenge:\n" .
			decode_base64( $node->data() )
		);
	}
	
	my $sasl = $heap->{'challenge'};
	my $conn = $sasl->client_new("xmpp", $heap->{'hostname'});
	$conn->client_start();

	my $step = $conn->client_step(decode_base64($node->data()));

	if ($heap->{'CONFIG'}->{'debug'}) {
		&debug_message("Decoded Response:\n$step");
	}

	$step =~ s/\s+//go;
	$step = encode_base64($step);
	$step =~ s/\s+//go;

	my $response = XNode->new('response', ['xmlns', +NS_XMPP_SASL]);
	$response->data($step);

	$kernel->yield('output_handler', $response);
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
	
	if($node->name() eq 'stream:stream')
	{
		$heap->{'sid'} = $node->attr('id');
		return;
	}

	if($node->name() eq 'challenge')
	{
		$kernel->yield('challenge_response', $node);
		return;
	}

	if($node->name() eq 'failure' and $node->attr('xmlns') eq +NS_XMPP_SASL)
	{
		warn "SASL Negotiation Failed";
		$kernel->yield('shutdown');
		$kernel->post($heap->{'CONFIG'}->{'state_parent'},
			$heap->{'CONFIG'}->{'states'}->{'errorevent'},
			+PCJ_AUTHFAIL);
		return;
	}

	if($node->name() eq 'stream:features')
	{
		my $clist = $node->get_children_hash();

		if(exists($clist->{'starttls'}))
		{
			my $starttls = XNode->new('starttls', ['xmlns', +NS_XMPP_TLS]);
			$kernel->yield('output_handler', $starttls);
			return;
		}

		if(exists($clist->{'mechanisms'})) 
		{
			my $mechs = $clist->{'mechanisms'}->get_sort_children();
			foreach my $mech (@$mechs)
			{
				if($mech->data() eq 'DIGEST-MD5')
				{
					$kernel->yield('set_auth', $mech->data());
					return;
				}
			}
			
			die "UNKNOWN MECHANISM: ".$node->to_str();
		}

		if(exists($clist->{'bind'}))
		{
			my $iq = XNode->new('iq', ['type', +IQ_SET]);
			$iq->insert_tag('bind', ['xmlns', +NS_XMPP_BIND])
				->insert_tag('resource')
				->data($heap->{'CONFIG'}->{'resource'});
			
			$heap->{'STARTSESSION'} = 1 if exists($clist->{'session'});
			$kernel->yield('return_to_sender', 'binding', $iq);
			return;
		}

		return;
	}

	if($node->name() eq 'proceed')
	{
		$kernel->yield('build_tls_wheel');
		$kernel->yield('initiate_stream');
		return;
	}

	if($node->name() eq 'success')
	{
		$heap->{'server'}->[2]->reset();
		$kernel->yield('initiate_stream');
		return;
	}
		
}

sub binding()
{
	my ($session, $kernel, $heap, $node) = @_[SESSION, KERNEL, HEAP, ARG0];

	my $attr = $node->attr('type');

	if($attr eq +IQ_RESULT)
	{
		if($heap->{'STARTSESSION'})
		{
			$heap->{'JID'} = $node->get_tag('bind')->get_tag('jid')->data();

			my $iq = XNode->new('iq', ['type', +IQ_SET]);
			$iq->insert_tag('session', ['xmlns', +NS_XMPP_SESSION]);

			$kernel->yield('return_to_sender', 'session_establish', $iq);
			return;
		
		} else {

			$heap->{'JID'} = $node->get_tag('bind')->get_tag('jid')->data();

			$kernel->post($heap->{'CONFIG'}->{'state_parent'},
				$heap->{'CONFIG'}->{'states'}->{'initfinish'},
				$heap->{'JID'});
			$kernel->state('got_server_input', \&input_handler);
		}
	} elsif($attr eq +IQ_ERROR) {

		my $error = $node->get_tag('error');

		if($error->attr('type') eq 'modify')
		{
			my $iq = XNode->new('iq', ['type', +IQ_SET]);
			$iq->insert_tag('bind', ['xmlns', +NS_XMPP_BIND])
				->insert_tag('resource')
				->data(&md5_hex(time().rand().$$.rand().$^T.rand()));
			$kernel->yield('return_to_sender', 'binding', $iq);
		
		} elsif($error->attr('type') eq 'cancel') {

			my $clist = $error->get_children_hash();
			
			if(exists($clist->{'conflict'}))
			{
				my $iq = XNode->new('iq', ['type', +IQ_SET]);
				$iq->insert_tag('bind', ['xmlns', +NS_XMPP_BIND])
					->insert_tag('resource')
					->data(&md5_hex(time().rand().$$.rand().$^T.rand()));
				$kernel->yield('return_to_sender', 'binding', $iq);
			
			} else {
			
				warn "Unable to BIND, yet binding required";
				warn $node->to_str();
				$kernel->yield('shutdown');
				$kernel->post($heap->{'CONFIG'}->{'state_parent'},
					$heap->{'CONFIG'}->{'states'}->{'errorevent'},
					+PCJ_BINDFAIL);
			}
			
		}
	}
}
		
sub session_establish()
{
	my ($session, $kernel, $heap, $node) = @_[SESSION, KERNEL, HEAP, ARG0];

	my $attr = $node->attr('type');
	
	if($attr eq +IQ_RESULT)
	{
		$kernel->post($heap->{'CONFIG'}->{'state_parent'},
			$heap->{'CONFIG'}->{'states'}->{'initfinish'},
			$heap->{'JID'});
	
		$kernel->state('got_server_input', \&input_handler);
	
	} elsif($attr eq +IQ_ERROR) {

		warn "Unable to intiate SESSION, yet session required";
		warn $node->to_str();
		$kernel->yield('shutdown');
		$kernel->post($heap->{'CONFIG'}->{'state_parent'},
			$heap->{'CONFIG'}->{'states'}->{'errorevent'},
			+PCJ_SESSFAIL);
	}

}
		

sub build_tls_wheel()
{
	my ($session, $kernel, $heap) = @_[SESSION, KERNEL, HEAP];
	
	delete $heap->{'server'};
	my $socket = &gensym();

	tie
	(
		*$socket, 
		'POE::Component::Jabber::Client::XMPP::TLS',
		$heap->{'socket'},
	) or die $!;
	
	$heap->{'server'} = POE::Wheel::ReadWrite->new
	(
		'Handle'		=> $socket,
		'Filter'		=> POE::Filter::XML->new(),
		'InputEvent'	=> 'got_server_input',
		'ErrorEvent'	=> 'got_server_error',
		'FlushedEvent'	=> 'got_server_flush',
	);

	return;
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

POE::Component::Jabber::Client::XMPP - A POE Component for XMPP Clients

=head1 SYNOPSIS

 use POE qw/ Component::Jabber::Client::XMPP Component::Jabber::Error /;
 use POE::Filter::XML::Node;
 use POE::Filter::XML::NS qw/ :JABBER :IQ /;

 POE::Component::Jabber->new(
   IP => 'jabber.server',
   PORT => '5222'
   HOSTNAME => 'jabber.server',
   USERNAME => 'username',
   PASSWORD => 'password',
   ALIAS => 'POCO',
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

POE::Component::Jabber::Client::XMPP is a simple connection broker to enable
communication using the IETF Proposed Standard XMPP. All of the steps to
initiate the connection, negotiate TLS, negotiate SASL, binding, and session
establishment are all handled for the end developer. Once INITFINISH is fired
the developer has a completed XMPP connection for which to send raw XML or
even send POE::Filter::XML::Nodes.

=head1 METHODS

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

=item USERNAME

The username to be used in SASL authentication (DIGEST-MD5)

=item PASSWORD

The password to be used in SASL authentication (DIGEST-MD5)

=item RESOURCE

The resource that will be used for binding and session establishment.

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

=head1 NOTES AND BUGS

This is a connection broker. We are not going to wipe your ass for you :)

=head1 AUTHOR

Copyright (c) 2003, 2004 Nicholas Perez. Distributed under the GPL.

=cut
