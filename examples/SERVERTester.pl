#!/usr/bin/perl

use warnings;
use strict;

use POE qw/Component::Jabber::Server/;

POE::Component::Jabber::Server->new
(
	'ip'				=> '127.0.0.1',
	'port' 				=> '5222',
	'hostname'			=> 'localhost',
	'registrar'			=> 'foo.db',
	'roster'			=> 'roster.db',
	'idle_check'		=> '30',
	'idle_timeout'		=> '10',
	'bandwidth_limit'	=> '10000',
	'private'			=> './keys/privkey.pem',
	'certificate'		=> './keys/server.pem',

	'debug'				=> '1',
);

$poe_kernel->run();


