package POE::Component::Jabber::Server::PresenceManager;

use strict;
use warnings;

use POE;
use POE::Filter::XML::Utils;

sub new()
{
	shift;
	my $config = shift;
	my $route = shift;
	my $roster = shift;
	
	POE::Session->create(
		inline_states => {
			_start =>
			sub
			{
				$_[KERNEL]->alias_set('PresenceManager');
				$_[HEAP]->{'JIDS'} = {};
			},
			_stop =>
			sub
			{
				$_[KERNEL]->alias_remove();
			},

			process	=> \&process,
			route	=> \&route,

		},
		heap => { CONFIG => $config, ROUTE => $route, ROSTER => $roster },
		options => { debug => $config->{'debug'}, trace => $config->{'debug'} }
	);

	return undef;
}

sub route()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];

	my $jid = $heap->{'ROUTE'}->get_jid_from_sid($sid);
	my $roster = $heap->{'ROSTER'}->get_roster(&get_user($jid));
	my $attrs = $node->get_attrs();
	
	
	
}
sub process()
{
	my ($kernel, $heap, $node, $sid) = @_[KERNEL, HEAP, ARG0, ARG1];

	my $jid = $heap->{'ROUTE'}->get_jid_from_sid($sid);
	my $roster = $heap->{'ROSTER'}->get_roster(&get_user($jid));
	
	my $old = delete $heap->{'JIDS'}->{$jid};
	$heap->{'JIDS'}->{$jid} = $node->clone();
	
	$node->attr('from', $jid);
	
	foreach my $item (keys %$roster)
	{
		if($roster->{$item}->{'sub'} eq 'from' and
			$heap->{'ROUTE'}->check_baseroute($item))
		{
			my $map = $heap->{'ROUTE'}->get_map_from_jid($item);
			foreach my $res (keys %$map)
			{
				next if $res eq 'default';
				my $bare = &get_bare($item);
				my $full = $bare.'/'.$res;
				next unless exists $heap->{'JIDS'}->{$full};
				my $presence = $node->clone();
				$presence->attr('to', $full);
				$kernel->call($map->{$res}, 'output_handler', $presence);
			}
		}

		if($roster->{$item}->{'sub'} eq 'to' and
			$heap->{'ROUTE'}->check_baseroute($item))
		{
			my $map = $heap->{'ROUTE'}->get_map_from_jid($item);
			foreach my $res (keys %$map)
			{
				next if $res eq 'default';
				my $bare = &get_bare($item);
				my $full = $bare.'/'.$res;
				next unless exists $heap->{'JIDS'}->{$full};
				my $presence = $heap->{'JIDS'}->{$full}->clone();
				$presence->attr('to', $jid);
				$presence->attr('from', $full);
				$kernel->call($sid, 'output_handler', $presence);
			}
		}

		if($roster->{$item}->{'sub'} eq 'both' and
			$heap->{'ROUTE'}->check_baseroute($item))
		{
			my $map = $heap->{'ROUTE'}->get_map_from_jid($item);
			foreach my $res (keys %$map)
			{
				next if $res eq 'default';
				my $bare = &get_bare($item);
				my $full = $bare.'/'.$res;
				next unless exists $heap->{'JIDS'}->{$full};
				my $presence = $node->clone();
				$presence->attr('to', $item);
				$kernel->call($map->{$res}, 'output_handler', $presence);
				my $return = $heap->{'JIDS'}->{$full}->clone();
				$return->attr('to', $jid);
				$return->attr('from', $item);
				$kernel->call($sid, 'output_handler', $presence);
			}
		}
	}
}


