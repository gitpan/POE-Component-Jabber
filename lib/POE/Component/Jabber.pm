package POE::Component::Jabber;

#this is of course tenative
our $VERSION = '1.0';
		
1;

__END__

=pod

=head1 NAME

POE::Component::Jabber - A POE Component for communicating over Jabber

=head1 SYNOPSIS

POE::Component::Jabber is not meant to be used directly. Please use one of the
subclasses of Client.

=head1 DESCRIPTION

POE::Component::Jabber is a module that simplies for the POE developer, access
to the Jabber protocol through the use of one of the four Client classes. With 
built in events for common Jabber packets, all a POE developer need do is 
provide an event and arguments for most events so the responses to the 
requests can be properly handled by the coder.

Please see the Client classes for more detailed descriptions of the events
provided.

=head1 AUTHOR

Copyright (c) 2003, 2004 Nicholas Perez. Distributed under the GPL.
See LICENSE for further details

=cut

