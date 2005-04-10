#!/usr/bin/perl

use POE::Preprocessor;
const XNode POE::Filter::XML::Node

use warnings;
use strict;

use POE qw/ Component::Jabber::Client::XMPP Component::Jabber::Error /;
use POE::Filter::XML::Node;
use POE::Filter::XML::NS qw/ :JABBER :IQ /;
use List::Util qw/ shuffle /;

POE::Session->create(
	options => { debug => 1, trace => 1},
	inline_states => {
		_start =>
			sub
			{
				my ($kernel, $heap) = @_[KERNEL, HEAP];
				$kernel->alias_set('Tester');
				
				POE::Component::Jabber::Client::XMPP->new(
					IP => 'localhost',
					PORT => '5222',
					HOSTNAME => 'localhost',
					USERNAME => 'test01',
					PASSWORD => 'test01',
					ALIAS => 'COMPONENT',
					DEBUG => '1',
					STATE_PARENT => 'Tester',
					STATES => {
						InitFinish => 'init_finished',
						InputEvent => 'input_event',
						ErrorEvent => 'error_event',
					}
				);
			},

		_stop =>
			sub
			{
				my $kernel = $_[KERNEL];
				$kernel->alias_remove();
			},

		delay_start => \&delay_start,
		input_event => \&input_event,
		error_event => \&error_event,
		init_finished => \&init_finished,
		test_message => \&test_message,
		output_event => \&output_event,
		return_event => \&return_event,
				
	}
);

sub init_finished()
{
	my ($kernel, $sender, $heap, $jid) = @_[KERNEL, SENDER, HEAP, ARG0];
	
	print "INIT FINISHED!\n";
	print "JID: $jid \n";
	print "SID: ".$sender->ID()."\n\n";
	
	$heap->{'jid'} = $jid;
	$heap->{'sid'} = $sender->ID();
	$kernel->delay_add('test_message', int(rand(10)));
	
}

sub input_event()
{
	my ($kernel, $heap, $node) = @_[KERNEL, HEAP, ARG0];
	
	print "\n===PACKET RECEIVED===\n";
	print $node->to_str() . "\n";
	print "=====================\n\n";
	
	$kernel->delay_add('test_message', int(rand(10)));
		
}

sub test_message()
{
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	
	my $node = XNode->new('message');
	$node->attr('to', $heap->{'jid'});
	$node->insert_tag('body')->data('This is a Test');
	
	$kernel->yield('output_event', $node, $heap->{'sid'});

}

sub output_event()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];
	
	print "\n===PACKET SENT===\n";
	print $node->to_str() . "\n";
	print "=================\n\n";
	
	$kernel->post($sid, 'output_handler', $node);
}

sub return_event()
{
	my $node = $_[ARG0];
	
	print "###Our return event was fired!###\n";
	print $node->to_str()."\n";
	print "#################################\n";
}

sub error_event()
{
	my ($kernel, $sender, $heap, $error) = @_[KERNEL, SENDER, HEAP, ARG0];

	if($error == +PCJ_SOCKFAIL)
	{
		my ($call, $code, $err) = @_[ARG1..ARG3];
		print "Socket error: $call, $code, $err\n";
	
	} elsif($error == +PCJ_SOCKDISC) {
		
		print "We got disconneted\n";
		print "Reconnecting!\n";
		$kernel->post($sender, 'reconnect_to_server');

	} elsif ($error == +PCJ_AUTHFAIL) {

		print "Failed to authenticate\n";

	} elsif ($error == +PCJ_BINDFAIL) {

		print "Failed to bind a resource\n";
	
	} elsif ($error == +PCJ_SESSFAIL) {

		print "Failed to establish a session\n";
	}
}
	
POE::Kernel->run();
