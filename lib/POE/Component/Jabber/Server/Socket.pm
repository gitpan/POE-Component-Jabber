package POE::Component::Jabber::Server::Socket;
use POE::Preprocessor;
const XNode POE::Filter::XML::Node
use strict;
use warnings;

use POE qw/ Wheel::ReadWrite Driver::SysRW /;
use POE::Component::Jabber::Server::Socket::STLS;
use POE::Filter::XML;
use POE::Filter::XML::Node;
use POE::Filter::XML::NS qw/ :JABBER /;
use Digest::MD5 qw/ md5 md5_hex /;
use Symbol qw/ gensym /;
use MIME::Base64;

######################
# Socket
######################

sub new()
{
	shift;
	my ($config, $route, $socket) = @_;
	
	POE::Session->create(
		inline_states	=> {
			_start	=> \&build_socket,
			_stop	=> \&cleanup,

			destroy_socket => \&destroy_socket,
			
			input_handler		=> \&init_input_handler,
			step_tls			=> \&step_tls,
			step_sasl			=> \&step_sasl,
			step_opt			=> \&step_opt,
			output_handler		=> \&output_handler,
			flush_handler		=> \&init_flush_handler,
			error_handler		=> \&error_handler,
			kill_socket			=> \&kill_socket,
			data_gather 		=> \&data_gather,
			check_limit			=> \&check_limit,
			get_total_bytes		=> \&get_total_bytes,
			get_avg_use			=> \&get_avg_use,
			check_last_active	=> \&check_last_active,
			stream_error		=> \&stream_error,
			stream_start		=> \&stream_start,
			stream_features		=> \&stream_features,
		},
		heap => { 'socket' => $socket, 'CONFIG' => $config , 'ROUTE' => $route},
		options => { debug => $config->{'debug'}, trace => $config->{'debug'} }
	);
}

sub build_socket()
{
	my ($session, $heap, $kernel) = @_[SESSION, HEAP, KERNEL];
	
	$heap->{'callback'} = sub{ $kernel->call($session, 'stream_error'); };
	$heap->{'filter'} = POE::Filter::XML->new(undef, $heap->{'callback'});
	$heap->{'driver'} = POE::Driver::SysRW->new(BlockSize => 4096);
	$heap->{'s_wheel'} = POE::Wheel::ReadWrite->new(
		Handle		=> $heap->{'socket'},
		Driver		=> $heap->{'driver'},
		Filter		=> $heap->{'filter'},
		InputEvent	=> 'input_handler',
		ErrorEvent	=> 'error_handler',
		FlushedEvent => 'flush_handler',
	);

	$kernel->call('SocketServer', 'post_socket', $session->ID());
	$heap->{'birth'} = time();
	$heap->{'bytes'} = 0;
	$heap->{'last_check'} = 0;
	$heap->{'kill_socket'} = 0;
	$heap->{'last_active'} = $heap->{'birth'};
	$heap->{'STAGE'} = 1;
	$heap->{'tries'} = 0;

}

sub step_tls()
{
	my ($session, $heap, $kernel) = @_[SESSION, HEAP, KERNEL];

	my $socket = &gensym();
	$heap->{'filter'}->reset();
	delete $heap->{'s_wheel'};
	
	tie
	(
		*$socket,
		'POE::Component::Jabber::Server::Socket::STLS',
		$heap->{'socket'},
		$heap->{'CONFIG'}->{'private'},
		$heap->{'CONFIG'}->{'certificate'},
	) or die $!;

	$heap->{'socket'} = $socket;
	
	$heap->{'s_wheel'} = POE::Wheel::ReadWrite->new(
		'Handle'		=> $heap->{'socket'},
		'Driver'		=> $heap->{'driver'},
		'Filter'		=> $heap->{'filter'},
		'InputEvent'	=> 'input_handler',
		'ErrorEvent'	=> 'error_handler',
		'FlushedEvent'	=> 'flush_handler',
	);
	my $time = time();
	$heap->{'last_active'} = $time;
}

sub step_sasl()
{
	# just reset the filter, no need to rebuild wheel
	$_[HEAP]->{'filter'}->reset();
	
	$_[HEAP]->{'last_active'} = time();
}

sub step_opt()
{
	my ($heap, $kernel) = @_[HEAP, KERNEL];

	# hotswap states without rebuilding the wheel
	$kernel->state('input_handler', \&input_handler);
	$kernel->state('flush_handler', \&flush_handler);

	$heap->{'last_active'} = time();
}
	
	
sub destroy_socket()
{
	my $heap = $_[HEAP];

	delete $heap->{'callback'};
	delete $heap->{'filter'};
	delete $heap->{'driver'};
	delete $heap->{'s_wheel'};
	# must explicitly close SSL socket :(
	$heap->{'socket'}->close();
	
}

sub cleanup()
{
	my ($session, $kernel, $heap) = @_[SESSION, KERNEL, HEAP];
	
	$kernel->call('SocketServer', 'remove_socket', $session->ID());
	$heap->{'ROUTE'}->delete_resource($session->ID());
}

sub stream_start()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	my $stream = XNode->new('stream:stream')->stream_start(1);
	$stream->insert_attrs(
	['xmlns', +NS_JABBER_CLIENT,
	'xmlns:stream', +XMLNS_STREAM,
	'from', $heap->{'CONFIG'}->{'hostname'},
	'version', '1.0']);

	$kernel->yield('output_handler', $stream);
}

sub stream_features()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	
	my $feats = XNode->new('stream:features');
	
	if($heap->{'STAGE'} == 1)
	{
		$feats->insert_tag('starttls', ['xmlns', +NS_XMPP_TLS])
			->insert_tag('required');
		$feats->insert_tag('mechanisms', ['xmlns', +NS_XMPP_SASL])
			->insert_tag('mechanism')->data('DIGEST-MD5');
	
	} elsif($heap->{'STAGE'} == 3) {

		$feats->insert_tag('mechanisms', ['xmlns', +NS_XMPP_SASL])
			->insert_tag('mechanism')->data('DIGEST-MD5');
	
	} elsif($heap->{'STAGE'} == 7) {

		$feats->insert_tag('bind', ['xmlns', +NS_XMPP_BIND]);
		$feats->insert_tag('session', ['xmlns', +NS_XMPP_SESSION]);
	}
	
	$kernel->yield('output_handler', $feats);
}

sub init_input_handler()
{
	my ($session, $kernel, $heap, $data) = @_[SESSION, KERNEL, HEAP, ARG0];
	
	if($data->name() eq 'stream:stream' and $data->stream_start())
	{
		my $attrs = $data->get_attrs();
		if(exists($attrs->{'to'}) and exists($attrs->{'xmlns'})
		and exists($attrs->{'xmlns:stream'}) 
		and exists($attrs->{'version'}))
		{
			if($attrs->{'to'} ne $heap->{'CONFIG'}->{'hostname'})
			{
				$kernel->call($session, 'stream_error', 'cancel', 
					'host-unknown');
			
			} elsif($attrs->{'xmlns'} ne +NS_JABBER_CLIENT or
				$attrs->{'xmlns:stream'} ne +XMLNS_STREAM) {
				
				$kernel->call($session, 'stream_error', 'cancel', 
					'invalid-namespace');

			} elsif($attrs->{'version'} ne '1.0') {
			
				$kernel->call($session, 'stream_error', 'cancel', 
					'unsupported-version');
			
			} else {

				$kernel->yield('stream_start');
				$kernel->yield('stream_features');
				
				if($heap->{'STAGE'} == 7)
				{
					$kernel->yield('step_opt');
					# At this point, we need a base jid of some sort
					# so I am going to stuff /something/ into RouteTable
					# or else SelfRouter is going to have no clue who the fuck
					# the binder is.
					#
					# Bare jid is stored directly after sucessful auth

					$heap->{'ROUTE'}->create_route(
						$session->ID(), $heap->{'JID'});
					return;
				}
			}
		
		} else {

			$kernel->call($session, 'stream_error', 'cancel', 
				'undefined-condition');
		}
		
	} elsif($data->name() eq 'starttls' and $heap->{'STAGE'} == 1) {

		my $proceed = XNode->new('proceed', ['xmlns', +NS_XMPP_TLS]);

		$kernel->yield('output_handler', $proceed);
		$heap->{'STAGE'}++;
	
	} elsif($data->name() eq 'auth' and $heap->{'STAGE'} == 3) {

		my $attrs = $data->get_attrs();
		if(!exists($attrs->{'mechanism'}) or 
			$attrs->{'mechanism'} ne 'DIGEST-MD5')
		{
			my $fail = XNode->new('failure', ['xmlns', +NS_XMPP_SASL]);
			$fail->insert_tag('invalid-mechanism');

			$kernel->call($session, 'stream_error', 'wait', $fail);
			return;
		}
	
		my $nonce = &md5_hex(rand().time().rand().$^T.rand().$$);

		my $sasl = 'realm="'.$heap->{'CONFIG'}->{'hostname'}.'",nonce="'.
		$nonce.'",qop="auth",charset="utf-8",algorithm="md5-sess"';

		$sasl = &encode_base64($sasl);

		my $challenge = XNode->new('challenge', ['xmlns', +NS_XMPP_SASL])
			->data($sasl);

		$heap->{'STAGE'}++;
		$heap->{'nonce'} = $nonce;
		$kernel->yield('output_handler', $challenge);
	
	} elsif($data->name() eq 'response' and $heap->{'STAGE'} == 4) {

		my $decoded = &decode_base64($data->data());
		my @pairs = split(',', $decoded);
		my $hash = {};
		
		foreach my $pair (@pairs)
		{
			my ($attrib, $value) = split('=', $pair);
			$value =~ s/[\"\']+//go;
			
			if(exists($hash->{$attrib}))
			{
				my $fail = XNode->new('failure', ['xmlns', +NS_XMPP_SASL]);
				$fail->insert_tag('temporary-auth-failure');

				$kernel->call($session, 'stream_error', 'wait', $fail);
				return;
			}
			
			$hash->{$attrib} = $value;
		}

		if(!exists($hash->{'username'}) or !exists($hash->{'realm'}) or
		!exists($hash->{'nonce'}) or !exists($hash->{'cnonce'}) or
		!exists($hash->{'response'}) or !exists($hash->{'charset'}) or
		!exists($hash->{'nc'}))
		{
			my $fail = XNode->new('failure', ['xmlns', +NS_XMPP_SASL]);
			$fail->insert_tag('temporary-auth-failure');

			$kernel->call($session, 'stream_error', 'wait', $fail);
			return;
		
		} else {
			
			my $password = $heap->{'ROUTE'}->get_auth($hash->{'username'});

			my $A1 = 
			join
			(':', 
				&md5
				(
					join
					(':', 
						$hash->{'username'}, 
						$heap->{'CONFIG'}->{'hostname'}, 
						$password
					)
				),
				$heap->{'nonce'}, $hash->{'cnonce'}
			);
			
			my $A2 = "AUTHENTICATE:" . $hash->{'digest-uri'};

			my $check = 
			&md5_hex
			(
				join
				(
					':', &md5_hex($A1), $heap->{'nonce'}, $hash->{'nc'},
					$hash->{'cnonce'}, $hash->{'qop'}, &md5_hex($A2)
				)
			);
			
			if($check ne $hash->{'response'})
			{
				my $fail = XNode->new('failure', ['xmlns', +NS_XMPP_SASL]);
				$fail->insert_tag('temporary-auth-failure');

				$kernel->call($session, 'stream_error', 'wait', $fail);
				return;
			
			} else {

				my $rspauth = 
				&md5_hex
				(
					join
					(
						':', &md5_hex($A1), $heap->{'nonce'}, $hash->{'nc'},
						$hash->{'cnonce'}, $hash->{'qop'}, 
						&md5_hex(':'.$hash->{'digest-uri'})
					)
				);
				
				my $rsvp = 'rspauth="'.$rspauth.'"';
				my $challenge = XNode->new('challenge', 
				['xmlns', +NS_XMPP_SASL])->data(&encode_base64($rsvp));

				$kernel->yield('output_handler', $challenge);
				$heap->{'STAGE'}++;

				# build the bare jid for this socket so we can bind it later

				$heap->{'JID'} = $hash->{'username'}.'@'.
					$heap->{'CONFIG'}->{'hostname'};
			}
		}
	} elsif($data->name() eq 'response' and $heap->{'STAGE'} == 5) {

		my $success = XNode->new('success', ['xmlns', +NS_XMPP_SASL]);
		$kernel->yield('output_handler', $success);
		$heap->{'STAGE'}++;
	
	} else {

		# stages don't match with packet received obviously
		# send back an error and close the stream
		$kernel->call($session, 'stream_error', 'cancel', 'undefined-condition');
	}
}

sub input_handler()
{
	my ($session, $kernel, $heap, $data) = @_[SESSION, KERNEL, HEAP, ARG0];
	
	if($kernel->call($session, 'check_limit'))
	{	
		$kernel->call($session, 'gather_data', length($data));
		$kernel->post('InputHandler', 'route', $data, $session->ID());
		
	} else {
		
		$kernel->yield('input_handler', $data);
	}
}

sub output_handler()
{
	my ($heap, $data) = @_[HEAP, ARG0];
	
	return unless defined $heap->{'s_wheel'};
	$heap->{'s_wheel'}->put($data);

}

sub kill_socket()
{
	my $heap = $_[HEAP];
	$heap->{'kill_socket'} = 1;
}

sub stream_error()
{
	my ($kernel, $heap, $session, $type, $condition) = 
	@_[KERNEL, HEAP, SESSION, ARG0, ARG1];
	
	if($type eq 'wait')
	{
		$heap->{'tries'}++;

		if($heap->{'tries'} > 2)
		{
			$kernel->yield('output_handler', $condition);
			$kernel->yield('kill_socket');
			$kernel->yield('output_handler', 
				XNode->new('stream:stream')->stream_end(1));

		} else {

			$kernel->yield('output_handler', $condition);
		}
	
	} elsif($type eq 'cancel') {

		my $error = XNode->new('stream:error');
		$error->insert_tag($condition, ['xmlns', +NS_XMPP_STREAMS]);
		my $end = XNode->new('stream:stream')->stream_end(1);
		
		$kernel->yield('output_handler', $error);
		$kernel->yield('kill_socket');
		$kernel->yield('output_handler', $end);
	}
}

sub init_flush_handler()
{
	my ($kernel, $heap, $session) = @_[KERNEL, HEAP, SESSION];
	
	if($heap->{'kill_socket'})
	{
		$kernel->yield('destroy_socket');
		return;
	}

	if($heap->{'STAGE'} == 2)
	{
		$kernel->yield('step_tls');
		$heap->{'STAGE'}++;
	
	} elsif($heap->{'STAGE'} == 6) {

		$kernel->yield('step_sasl');
		$heap->{'STAGE'}++;
	}
	
}

sub flush_handler()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	if($heap->{'kill_socket'})
	{
		$kernel->yield('destroy_socket');
	}
}

sub error_handler()
{
	my ($kernel, $heap, $session) = @_[KERNEL, HEAP, SESSION];

	$kernel->yield('destroy_socket');
}

sub get_total_bytes()
{
	my $heap = $_[HEAP];

	return $heap->{'bytes'};
}

sub get_avg_use()
{
	my $heap = $_[HEAP];
	
	my $time = time() - $heap->{'birth'};
	
	return ($heap->{'bytes'} / $time);
}
	

sub gather_data()
{
	my ($heap, $data) = @_[HEAP, ARG0];

	$heap->{'bytes'} += $data;
	$heap->{'last_active'} = time();
}

sub check_limit()
{
	my $heap = $_[HEAP];
	
	my $previous = $heap->{'last_check'};
	my $time = time() - $heap->{'birth'};
	if($time == 0) { ++$time; }
	my $current = ($heap->{'bytes'} / $time);
	$current = ($current + $previous) / 2;
	$heap->{'last_check'} = $current;

	if($current < $heap->{'CONFIG'}->{'bandwidth_limit'})
	{
		return 1;
	}

	return 0;
}

sub check_last_active()
{
	my $heap = $_[HEAP];

	return $heap->{'last_active'};
}

1;
