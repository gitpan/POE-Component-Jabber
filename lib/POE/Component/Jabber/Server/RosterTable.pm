package POE::Component::Jabber::Server::RosterTable;

use strict;
use warnings;

use DBI;

#######################
# RouteTable
#######################

sub new()
{
	my ($class, $config) = @_;

	my $self = {};
	bless($self, $class);

	$self->{'CONFIG'} = $config;

	$self->{'DB'} = DBI->connect(
		'dbi:SQLite:dbname=' .
		$self->{'CONFIG'}->{'roster'}
	);

	my @tables = $self->{'DB'}->tables();

	foreach my $table (@tables)
	{
		if($table =~ /roster/)
		{
			$self->{'ROSTER'} = 1;
			last;
		}
	}
	if(not $self->{'ROSTER'})
	{
		my $sth = $self->{'DB'}->prepare(
			'create table roster (username varchar(1024), 
			jid varchar(2048), sub varchar(16),
			ask varchar(16), name varchar(1024), 
			groups varchar(1024))'
		);
		$sth->execute();
	}
	$self->{'GET_ROSTER'} = $self->{'DB'}->prepare(
		'select jid, sub, ask, name, groups
		from roster where username = ?'
	);
	$self->{'GET_ROSTER_ITEM'} = $self->{'DB'}->prepare(
		'select jid, sub, ask, name, groups
		from roster where username = ? and jid = ?'
	);
	$self->{'UPDATE_ROSTER'} = $self->{'DB'}->prepare(
		'update roster set sub = ?, ask = ?, name = ?, groups = ?
		where username = ? and jid = ?'
	);
	$self->{'SET_ROSTER'} = $self->{'DB'}->prepare(
		'insert into roster 
		(username, jid, sub, ask, name, groups) 
		values (?,?,?,?,?,?)'
	);
}

sub DESTROY()
{
	my $self = shift;

	delete $self->{'GET_ROSTER'};
	delete $self->{'GET_ROSTER_ITEM'};
	delete $self->{'UPDATE_ROSTER'};
	delete $self->{'SET_ROSTER'};
	$self->{'DB'}->disconnect();
	undef $self->{'DB'};
}

sub get_roster()
{
	my ($self, $name) =  @_;

	$self->{'GET_ROSTER'}->execute($name);
	
	my $hash = {};
	while (my $array = $self->{'GET_ROSTER'}->fetchrow_arrayref())
	{
		$hash->{$array->[0]}->{'sub'} = $array->[1];
		$hash->{$array->[0]}->{'ask'} = $array->[2];
		$hash->{$array->[0]}->{'name'} = $array->[3];
		$hash->{$array->[0]}->{'groups'} = [];
		@{$hash->{$array->[0]}->{'groups'}} = split(/:/, $array->[4]);
	}

	return $hash;
}

sub get_roster_item()
{
	my ($self, $name, $jid) = @_;

	$self->{'GET_ROSTER_ITEM'}->execute($name, $jid);

	my $hash = {};
	my $array = $self->{'GET_ROSTER_ITEM'}->fetchrow_arrayref();

	$hash->{$array->[0]}->{'sub'} = $array->[1];
	$hash->{$array->[0]}->{'ask'} = $array->[2];
	$hash->{$array->[0]}->{'name'} = $array->[3];
	$hash->{$array->[0]}->{'groups'} = [];
	@{$hash->{$array->[0]}->{'groups'}} = split(/:/, $array->[4]);

	return $hash;
}

sub update_roster()
{
	my ($self, $usr, $jid, $sub, $ask, $name, $groups) = @_;

	$self->{'UPDATE_ROSTER'}->execute($sub, $ask, $name, $groups, $usr, $jid);

	return;
}

sub set_roster()
{
	my ($self, $usr, $jid, $sub, $ask, $name, $groups) = @_;

	$self->{'SET_ROSTER'}->execute($usr, $jid, $sub, $ask, $name, $groups);

	return;
}

1;
