package POE::Component::Jabber::Server::RouteTable;

use strict;
use warnings;

use DBI;
use POE::Filter::XML::Utils;

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
		$self->{'CONFIG'}->{'registrar'}, {'RaiseError'=>1}
	);

	my @tables = $self->{'DB'}->tables();

	foreach my $table (@tables)
	{
		if($table =~ /registrar/)
		{
			$self->{'REGISTAR'} = 1;
			last;
		}
	}

	if(not $self->{'REGISTAR'})
	{
		my $sth = $self->{'DB'}->prepare(
			'create table registrar (username varchar(1024),'.
			'password varchar(1024))'
		);

		$sth->execute();
	}

	$self->{'CHECK_DB'} = $self->{'DB'}->prepare(
		'select * from registrar where ? = username'
	);

	$self->{'SET_REG'} = $self->{'DB'}->prepare(
		'insert into registrar (username, password)	values (?,?)'
	);
	$self->{'DEL_REG'} = $self->{'DB'}->prepare(
		'delete from registrar where username = ? and password = ?'
	);

	$self->{'UPDATE_REG'} = $self->{'DB'}->prepare(
		'update registrar set password = ? where username = ?'
	);
	$self->{'JIDS'} = {};
	$self->{'SIDS'} = {};

	return $self;
}

sub DESTROY()
{
	my $self = shift;

	delete $self->{'UPDATE_REG'};
	delete $self->{'CHECK_DB'};
	delete $self->{'SET_REG'};
	delete $self->{'DEL_REG'};
	$self->{'DB'}->disconnect();
	undef $self->{'DB'};
}

sub check_route()
{
	my ($self, $fjid, $bool) = @_;
	
	my ($jid, $reso) = split('/', $fjid);

	if(not defined($reso))
	{
		my $sid = $self->{'JIDS'}->{$jid}->{'default'};
		my $sjid = $self->{'SIDS'}->{$sid};
		
		(undef, $reso) = split('/', $sjid);
	}

	if(exists($self->{'JIDS'}->{$jid}->{'resources'}->{$reso}))
	{
		if(defined($bool))
		{
			return 1;
		}

		return $self->{'JIDS'}->{$jid}->{'resources'}->{$reso}->[0];

	} else {

		return 0;
	}
}

sub get_map_from_jid()
{
	my ($self, $fjid) = @_;

	my ($jid, $reso) = split('/', $fjid);

	return $self->{'JIDS'}->{$jid}->{'resources'};
}

sub get_sid_from_jid()
{
	my ($self, $fjid) = @_;
	
	my ($jid, $reso) = split('/', $fjid);

	if(not defined $reso)
	{
		return $self->{'JIDS'}->{$jid}->{'default'};
	}
	return $self->{'JIDS'}->{$jid}->{'resources'}->{$reso}->[0];
}

sub get_jid_from_sid()
{
	my ($self, $sid) = @_;

	return $self->{'SIDS'}->{$sid};
}

sub create_route()
{
	my ($self, $sid, $jid) = @_;
	
	if(not exists $self->{'JIDS'}->{$jid})
	{
		$self->{'JIDS'}->{$jid}->{'default'} = $sid;
		$self->{'JIDS'}->{$jid}->{'resources'} = {};
		$self->{'SIDS'}->{$sid} = $jid;
	
	} else {

		$self->{'SIDS'}->{$sid} = $jid;
	}

}

sub add_resource()
{
	my ($self, $sid, $reso) = @_;
	
	my $jid = $self->{'SIDS'}->{$sid};
	$self->{'SIDS'}->{$sid} = $jid.'/'.$reso;
	$self->{'JIDS'}->{$jid}->{'resources'}->{$reso} = [];
	$self->{'JIDS'}->{$jid}->{'resources'}->{$reso}->[0] = $sid;
	$self->{'JIDS'}->{$jid}->{'resources'}->{$reso}->[1] = 0;
}

sub check_resource()
{
	my ($self, $sid, $reso) = @_;

	my $jid = $self->{'SIDS'}->{$sid};
	my $bare = &get_bare_jid($jid);

	if(!exists($self->{'JIDS'}->{$bare}->{'resources'}->{$reso}))
	{
		return 1;

	} else {

		return 0;
	}
}

sub activate_resource()
{
	my ($self, $sid) = @_;

	my ($jid, $reso) = split('/', $self->{'SIDS'}->{$sid});
	$self->{'JIDS'}->{$jid}->{'resources'}->{$reso}->[1] = 1;
}

sub delete_resource()
{
	my ($self, $sid) = @_;
	
	return if not exists($self->{'SIDS'}->{$sid});
	my ($jid, $reso) = split('/', $self->{'SIDS'}->{$sid});
	delete $self->{'JIDS'}->{$jid}->{'resources'}->{$reso};
	delete $self->{'SIDS'}->{$sid};

	if(!keys %{$self->{'JIDS'}->{$jid}->{'resources'}})
	{
		delete $self->{'JIDS'}->{$jid};
	}
		
	return;
}

sub set_reg()
{
	my ($self, $name, $password) = @_;
	
	$self->{'SET_REG'}->execute($name, $password);

}

sub del_reg()
{
	my ($self, $name, $password) = @_;
	
	$self->{'DEL_REG'}->execute($name, $password);

}

sub set_auth()
{
	my ($self, $name, $password) = @_;

	$self->{'CHECK_DB'}->execute($name);
	
	my $array = $self->{'CHECK_DB'}->fetchrow_arrayref();
	
	if($array->[1] eq $password)
	{
		return 1;
		
	} else {
	
		return 0;
	}
}

sub get_auth()
{
	my ($self, $name) = @_;
	
	$self->{'CHECK_DB'}->execute($name);

	my $array = $self->{'CHECK_DB'}->fetchrow_arrayref();

	return $array->[1];
}

sub check_db()
{
	my ($self, $name) = @_;
	
	$self->{'CHECK_DB'}->execute($name);
	
	if(my $array_ref = $self->{'CHECK_DB'}->fetchrow_arrayref())
	{
		return 1;
	
	} else {
		
		return 0;
	}
}

sub update_reg()
{
	my ($self, $name, $password) = @_;

	$self->{'UPDATE_REG'}->execute($password, $name);
	
	return;
}


1;
