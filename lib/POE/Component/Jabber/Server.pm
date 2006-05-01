package POE::Component::Jabber::Server;
use Filter::Template;
const PCJS POE::Component::Jabber::Server
use warnings;
use strict;

use POE;
use PCJS::InputHandler;
use PCJS::RouteProcessor;
use PCJS::RouteTable;
use PCJS::RosterTable;
use PCJS::SelfRouter;
use PCJS::SocketServer;

our $VERSION = '1.21';

sub new()
{
	my $class = shift;
	my $name = $class . '->new()';
	die "$name requires an even number of arguments" if(@_ & 1);

	my $config = {};
	while($#_ != -1)
	{
		my $key = lc(shift(@_));
		my $value = shift(@_);
		$config->{$key} = $value;
	}

	my $route = PCJS::RouteTable->new($config);
	my $roster = PCJS::RosterTable->new($config);

	PCJS::InputHandler->new($config, $route);
	PCJS::SocketServer->new($config, $route);
	PCJS::SelfRouter->new($config, $route);
	PCJS::RouteProcessor->new($config, $route);

}

1;

