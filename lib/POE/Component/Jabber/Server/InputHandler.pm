package POE::Component::Jabber::Server::InputHandler;

use strict;
use warnings;

use POE;
use POE::Filter::XML::Utils;
use POE::Filter::XML::NS qw/ :JABBER :IQ /;

###################
# InputHandler
###################


sub new()
{
	shift;
	my $config = shift;
	my $route = shift;

	POE::Session->create(
		inline_states => {
			_start	=> 
			sub
			{ 
				my $kernel = $_[KERNEL]; 
				$kernel->alias_set('InputHandler');
			},
			_stop	=> 
			sub
			{ 
				my $kernel = $_[KERNEL]; 
				$kernel->alias_remove();
			},

			route	=> \&route,
		},
		heap => { CONFIG => $config, ROUTE => $route },
		options => { debug => $config->{'debug'}, trace => $config->{'debug'} }
	);
	return undef;
}

sub route()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];
	
	my $name = $node->name();
	my $dest = $node->attr('to');
	
	my $jid = $heap->{'ROUTE'}->get_jid_from_sid($sid);

	if ($name ne 'presence' and $name ne 'message' and $name ne 'iq')
	{
		$node = &get_stanza_error($node, 'bad-request', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
		return;
	}
	
	if(not defined($dest) or $dest eq $heap->{'CONFIG'}->{'hostname'})
	{
		if($name eq 'presence')
		{
			$kernel->post('PresenceManager', 'process', $node, $sid);
			return;
		
		} elsif($name eq 'iq') {

			my $clist = $node->get_children_hash();

			if(exists($clist->{'query'}) and
				$clist->{'query'}->attr('xmlns') eq +NS_JABBER_ROSTER)
			{
				$kernel->post('RosterManager', 'route', $node, $sid, $dest);
				return;
			}

			$kernel->post('SelfRouter', 'route', $node, $sid);
		}
		  
	} elsif($heap->{'ROUTE'}->check_route($jid)) {

		if($name eq 'presence')
		{
			$kernel->post('PresenceManager', 'route', $node, $sid, $dest);

		} elsif($name eq 'iq') {

			my $clist = $node->get_children_hash();
			
			if(exists($clist->{'query'}) and 
				$clist->{'query'}->attr('xmlns') eq +NS_JABBER_ROSTER)
			{

				$kernel->post('RosterManager', 'route', $node, $sid, $dest);
			}
	
		} else {
		
			$kernel->post('RouteProcessor', 'route', $node, $sid, $dest);
		}
	
	} else {
		
		$node = &get_stanza_error($node, 'not-acceptable', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
		return;
	}
		
}

1;
