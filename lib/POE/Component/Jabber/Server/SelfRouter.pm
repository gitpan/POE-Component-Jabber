package POE::Component::Jabber::Server::SelfRouter;

use strict;
use warnings;

use POE;
use POE::Filter::XML::Node;
use POE::Filter::XML::Utils;
use POE::Filter::XML::NS qw/ :JABBER :IQ /;
use Digest::MD5 qw/ md5_hex /;

sub new()
{
	shift;
	my $config = shift;
	my $route_table = shift;

	POE::Session->create(
		inline_states => {
			_start	=> sub{ my $kernel = $_[KERNEL];
						$kernel->alias_set('SelfRouter'); },
			_stop	=> sub{ my $kernel = $_[KERNEL];
						$kernel->alias_remove(); },

			'set_bind'		=> \&set_bind,
			'set_session'	=> \&set_session,

			'route'			=> \&route,	

			

		},
		options => { debug => $config->{'debug'}, trace => $config->{'debug'}},
		heap => { 
			'ROUTE' => $route_table,
			'CONFIG' => $config, 
			'EVENTS' => {
				'set' => {
					NS_XMPP_BIND()			=> 'set_bind',
					NS_XMPP_SESSION()		=> 'set_session',
				},
			}
		}
	);
}

sub route()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];

	my $attrs = $node->get_attrs();
	my $clist = $node->get_children();

	my $event = $heap->{'EVENTS'}->{$attrs->{'type'}}
		->{$clist->[0]->attr('xmlns')};
	
	$kernel->yield($event, $node, $sid);
	
}

sub set_session()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];

	if($heap->{'ROUTE'}->check_route(
	$heap->{'ROUTE'}->get_jid_from_sid($sid), 1))
	{
		$heap->{'ROUTE'}->activate_resource($sid);

		$node = &get_reply($node);
		$kernel->post($sid, 'output_handler', $node);
	
	} else {

		$node = &get_stanza_error($node, 'bad-request', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
	}
}

sub set_bind()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];
	
	if($heap->{'ROUTE'}->check_route(
	$heap->{'ROUTE'}->get_jid_from_sid($sid), 1))
	{
		$node = &get_stanza_error($node, 'bad-request', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
		return;
	}
	
	my $bind = $node->get_children()->[0];
	my $reso = $bind->get_children()->[0];
	
	if(not defined $reso)
	{
		my $resource = &md5_hex(rand().time().rand().$^T.rand().$$);
		$heap->{'ROUTE'}->add_resource($sid, $resource);

		my $fjid = $heap->{'ROUTE'}->get_jid_from_sid($sid);

		$node = &get_reply($node);
		$bind->insert_tag('jid')->data($fjid);

		$kernel->post($sid, 'output_handler', $node);
	
	} elsif($reso->name() eq 'resource') {

		my $resource = $reso->data();

		if($heap->{'ROUTE'}->check_resource($sid, $resource))
		{
			$heap->{'ROUTE'}->add_resource($sid, $resource);
			my $fjid = $heap->{'ROUTE'}->get_jid_from_sid($sid);

			$node = &get_reply($node);
			$bind->insert_tag('jid')->data($fjid);

			$kernel->post($sid, 'output_handler', $node);
		
		} else {

			$node = &get_stanza_error($node, 'conflict', 'cancel');
			$kernel->post($sid, 'output_handler', $node);
		}
		
	} else {

		$node = &get_stanza_error($node, 'bad-request', 'cancel');
		$kernel->post($sid, 'output_handler', $node);
	}
}

1;
