#!/usr/bin/perl

use POE::Preprocessor;
const XNode POE::Filter::XML::Node

use warnings;
use strict;

use POE qw/ Component::Jabber::Client::Component Component::Jabber::Error /;
use POE::Filter::XML::Node;
use POE::Filter::XML::NS qw/ :JABBER :IQ /;


POE::Session->create(
	options => { debug => 1, trace => 1},
	inline_states => {
		_start =>
			sub
			{
				my $kernel = $_[KERNEL];
				$kernel->alias_set('Tester');
				POE::Component::Jabber::Client::Component->new(
					IP => 'localhost',
					PORT => '10000',
					HOSTNAME => 'localhost',
					PASSWORD => 'password',
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
	my ($kernel, $heap) = @_[KERNEL, HEAP];
	
	print "INIT FINISHED!\n";
	$heap->{'jid'} = 'test.localhost';
	$kernel->yield('test_message');
}

sub input_event()
{
	my ($kernel, $heap, $node) = @_[KERNEL, HEAP, ARG0];
	
	print "\n===PACKET RECEIVED===\n";
	print $node->to_str() . "\n";
	print "=====================\n\n";
	
	if($node->name() eq 'message' and $node->attr('from') ne $heap->{'jid'})
	{
		$node->attr('to', $node->attr('from'));
		$node->attr('from', $heap->{'jid'});
		$kernel->yield('output_event', $node);
	}
		
}

sub test_message()
{
	my $kernel = $_[KERNEL];
	
	my $node = XNode->new('message');
	$node->attr('to', $_[HEAP]->{'jid'});
	$node->attr('from', $_[HEAP]->{'jid'});
	$node->insert_tag('body')->data('This is a Test');
	
	$kernel->post('COMPONENT', 'return_to_sender', 'return_event', $node);
}

sub output_event()
{
	my ($kernel, $node) = @_[KERNEL, ARG0];
	
	print "\n===PACKET SENT===\n";
	print $node->to_str() . "\n";
	print "=================\n\n";
	$kernel->post('COMPONENT', 'output_handler', $node);
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
	my $error = $_[ARG0];

	if($error == +PCJ_SOCKFAIL)
	{
		my ($call, $code, $err) = @_[ARG1..ARG3];
		print "Socket error: $call, $code, $err\n";

	} elsif($error == +PCJ_SOCKDISC) {

		print "We got disconneted\n";

	} elsif ($error == +PCJ_AUTHFAIL) {

		print "Failed to authenticate\n";

	} elsif ($error == +PCJ_BINDFAIL) {

		print "Failed to bind a resource\n";

	} elsif ($error == +PCJ_SESSFAIL) {

		print "Failed to establish a session\n";
	}
}

POE::Kernel->run();
