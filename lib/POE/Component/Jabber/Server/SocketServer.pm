package POE::Component::Jabber::Server::SocketServer;

use strict;
use warnings;

use POE qw/ Wheel::SocketFactory /;
use POE::Component::Jabber::Server::Socket;

######################
# SocketServer
######################

sub new()
{
	shift;
	my $config = shift;
	my $route = shift;

	POE::Session->create(
		inline_states => {
			_start	=> \&server_start,
			_stop	=> \&server_stop,

			new_socket	=> \&new_socket,
			die_socket	=> \&die_socket,
			post_socket	=> \&post_socket,
			remove_socket => \&remove_socket,

			prune	=> \&prune,
			
		},
		heap => {CONFIG => $config, ROUTE => $route},
		options => { debug => $config->{'debug'}, trace => $config->{'debug'}},
	);
	return undef;
}

sub post_socket()
{
	my ($heap, $socket_id) = @_[HEAP, ARG0];
	$heap->{'sockets'}->{$socket_id} = 1;
	
}

sub remove_socket()
{
	my ($heap, $socket_id) = @_[HEAP, ARG0];
	delete $heap->{'sockets'}->{$socket_id};
}

sub server_start()
{
	my ($heap, $kernel) = @_[HEAP, KERNEL];

	$kernel->alias_set('SocketServer');

	$heap->{'listener'} = POE::Wheel::SocketFactory->new(
		BindAddress	=> $heap->{'CONFIG'}->{'ip'},
		BindPort	=> $heap->{'CONFIG'}->{'port'},
		SocketProtocol	=> 'tcp',
		Reuse		=> 'yes',
		SuccessEvent	=> 'new_socket',
		FailureEvent	=> 'die_socket',
	);

	$kernel->delay('prune', $heap->{'CONFIG'}->{'idle_check'});
}

sub server_stop()
{
	my ($heap, $kernel) = @_[HEAP, KERNEL];
	$kernel->alias_remove('SocketServer');
	delete $heap->{listener};
	foreach my $socket_id (keys %{$heap->{'sockets'}})
	{
		$kernel->post($socket_id, 'destroy_socket');
	}
}

sub new_socket()
{
	my ($heap, $socket) = @_[HEAP, ARG0];

	POE::Component::Jabber::Server::Socket->new(
	$heap->{'CONFIG'}, $heap->{'ROUTE'}, $socket);
	return;
	
}

sub die_socket()
{
	my ($operation, $errno, $errmsg) = @_[ARG0..ARG2];
	warn "SocketServer: $operation failed. $errno: $errmsg";

}

sub prune()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];

	my $sockets = $heap->{'sockets'};
	foreach my $key (keys %$sockets)
	{
		my $last_activity = $kernel->call($key, 'check_last_active');
		my $c_time = time();
		if(($c_time - $last_activity) > $heap->{'CONFIG'}->{'idle_timeout'})
		{
			$kernel->post($key, 'stream_error', 'cancel', 
				'connection-timeout');
		}
	}

	$kernel->delay('prune', $heap->{'CONFIG'}->{'idle_check'});
}

1;
