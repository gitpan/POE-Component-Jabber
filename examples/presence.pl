#!/usr/bin/perl -w

=head1 Description

This is just a sample of how to use the PoCo::Jabber module.  It logs
into a jabber server and, provided that the logged in user has people
on its "buddies" list registered with that server, prints out presence
indicators.

=cut

use strict;
use POE qw( Component::Jabber );
use Jabber::NodeFactory;
use Jabber::NS qw( :all );


my $start = sub {
    my ( $kernel, $session, $heap ) = @_[ KERNEL, SESSION, HEAP ];

    POE::Component::Jabber->new( 'Paging Server' );

    $kernel->post( 'Paging Server', 'register', qw( authed authfailed ) );
    $kernel->post( 'Paging Server', 'connect', {
	host	    => 'example.com',
	user	    => 'unknown',
	resource    => 'poe',
	password    => '-----',
	debug	    => 0
    } );
};

my $setup = sub {
    my ( $kernel ) = $_[ KERNEL ];

    my $node = Jabber::NodeFactory->new()->newNode( 'presence' );
    $kernel->post( 'Paging Server', 'send', $node );
    $kernel->post( 'Paging Server', 'register', qw( presence ) );
};


my $presence = sub {
  my $person = $_[ ARG0 ];
  my $status = $person->getTag('status');

  $status &&= $status->data;
  $status ||= '???';

  warn $person->attr('from') . " => " . $status, "\n\n";
};

POE::Session->create( inline_states =>
		      { _start          => $start,
			jabber_authed   => $setup,
			jabber_authfailed => sub {die "Authentication Failed.\n"},
		        jabber_presence => $presence});
POE::Kernel->run();
