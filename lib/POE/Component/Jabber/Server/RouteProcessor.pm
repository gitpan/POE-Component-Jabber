#!/usr/bin/perl

use strict;
use warnings;

package POE::Component::Jabber::Server::RouteProcessor;

use POE;
use POE::Filter::XML::Utils;

sub new()
{
	shift;
	my $config = shift;
	my $route = shift;
	
	POE::Session->create(
		heap => { CONFIG => $config, ROUTE => $route},
		inline_states => {
			_start => 
				sub
				{
					$_[KERNEL]->alias_set('RouteProcessor');
				},
			_stop =>
				sub
				{
					$_[KERNEL]->alias_remove();
				},

			route => \&route,
		},
		options => { debug => $config->{'debug'}, trace => $config->{'debug'}},
	);

	return undef;
}

sub route()
{
	my ($kernel, $heap, $node, $sid, $dest) = 
	@_[KERNEL, HEAP, ARG0, ARG1, ARG2];

	if(!$heap->{'ROUTE'}->check_route(
	$heap->{'ROUTE'}->get_jid_from_sid($sid)))
	{
		$node = &get_stanza_error($node, 'not-acceptable', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
		return;
	}

	if($heap->{'ROUTE'}->check_route($dest)) 
	{
		my $from = $heap->{'ROUTE'}->get_jid_from_sid($sid);
		$node->attr('from', $from);
		my $to_sid = $heap->{'ROUTE'}->get_sid_from_jid($dest);
		$kernel->call($to_sid, 'output_handler', $node);
	
	} else {
		
		$node = &get_stanza_error($node, 'service-unavailable', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
	}
}

1;
