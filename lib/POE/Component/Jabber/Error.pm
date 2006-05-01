package POE::Component::Jabber::Error;
use warnings;
use strict;

use constant 
{
	'PCJ_SOCKFAIL' => 0,
	'PCJ_SOCKDISC' => 1,
	'PCJ_AUTHFAIL' => 2,
	'PCJ_BINDFAIL' => 3,
	'PCJ_SESSFAIL' => 4,
	'PCJ_SSLFAIL'  => 5,
	'PCJ_CONNFAIL' => 6,
};

require Exporter;
our $VERSION = '1.21';
our @ISA = qw/ Exporter /;
our @EXPORT = qw/ PCJ_SOCKFAIL PCJ_SOCKDISC 
	PCJ_AUTHFAIL PCJ_BINDFAIL PCJ_SESSFAIL PCJ_SSLFAIL PCJ_CONNFAIL/;

1;

__END__

=pod 

=head1 NAME

POE::Component::Jabber::Error - Error constants for use in PCJ

=head1 SYNOPSIS

 use POE::Component::Jabber::Error; # All constants imported

 sub error_handler()
 {
 	my $error = $_[ARG0];

	if($error == +PCJ_SOCKFAIL)
	{
		my ($call, $code, $err) = @_[ARG1..ARG3];
		print "Socket error: $call, $code, $err\n";
	
	} elsif ($error == +PCJ_SOCKDISC) {

		print "We got disconneted\n";
	
	} elsif ($error == +PCJ_AUTHFAIL) {

		print "Failed to authenticate\n";

	} elsif ($error == +PCJ_BINDFAIL) {

		print "Failed to bind a resource\n"; # XMPP/J2 Only

	} elsif ($error == +PCJ_SESSFAIL) {

		print "Failed to establish a session\n"; # XMPP Only
	
	} elsif ($error == +PCJ_SSLFAIL) {
		
		my $err = @_[+ARG1];
		print "TLS/SSL negotiation failed: $err\n"; #XMPP/J2 only
	}
 }

=head1 DESCRIPTION

POE::Component::Jabber::Error provides error constants for use in error
handlers to determine the type of error one of the Client classes encountered.

Simply `use`ing the class imports all of the constants

=head1 ERRORS

=over 4

=item PCJ_SOCKFAIL

There has been some sort of socket error. ARG1..ARG3 are what 
Client::TCP gave to the Client class.

See POE::Component::Client::TCP for further details on what is returned.

=item PCJ_SOCKDISC

The socket has been disconnected according to Client::TCP.

See POE::Component::Client::TCP for further details.

=item PCJ_AUTHFAIL

Authentication has failed.

=item PCJ_BINDFAIL

Resource/Domain binding has failed. XMPP/J2 Only

=item PCJ_SESSFAIL

Session establishment has failed. XMPP Only

=item PCJ_SSLFAIL

TLS/SSL negotiation has failed. ARG1 is what POE::Component::SSLify sets to $@
for your ever delightful information. XMPP/J2 Only

=back


=head1 NOTES

These errors aren't written in stone. They are written in vim. They are
subject to change. 

=head1 AUTHORS AND COPYRIGHT

Copyright (c) 2004,2005 Nicholas Perez. Released and distributed under the GPL.

=cut

