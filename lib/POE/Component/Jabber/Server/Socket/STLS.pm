# $Id: STLS.pm,v 1.2 2004/03/21 03:48:25 nick Exp $
# License and documentation are after __END__.

package POE::Component::Jabber::Server::Socket::STLS;

use warnings;
use strict;

use Carp qw(croak);

use vars qw($VERSION);
$VERSION = (qw($Revision: 1.2 $ ))[1];

use POE::Component::Jabber::Server::Socket::CTLS;
use vars qw(@ISA);
@ISA = qw(POE::Component::Jabber::Server::Socket::CTLS);

use Net::SSLeay qw(die_if_ssl_error ERROR_WANT_READ ERROR_WANT_WRITE);
use POSIX qw(F_GETFL F_SETFL O_NONBLOCK EAGAIN EWOULDBLOCK);

sub TIEHANDLE {
  my ($class, $socket, $key, $cert) = @_;

  # Validate the certificate.
  croak "no such file: $cert" unless -f $cert;
  croak "can't read file: $cert" unless -R $cert;

  # Net::SSLeay needs nonblocking for setup.
  my $flags = fcntl($socket, F_GETFL, 0) or die $!;
  until (fcntl($socket, F_SETFL, $flags | O_NONBLOCK)) {
    die $! unless $! == EAGAIN or $! == EWOULDBLOCK;
  }

  $class->_initialize();

  my $ctx = Net::SSLeay::CTX_new() or die_now("Failed to create SSL_CTX $!");
  my $ssl = Net::SSLeay::new($ctx) or die_now("Failed to create SSL $!");

  my $fileno = fileno($socket);

  Net::SSLeay::set_fd($ssl, $fileno);   # Must use fileno

  Net::SSLeay::use_RSAPrivateKey_file( $ssl,
                                       $key,
                                       &Net::SSLeay::FILETYPE_PEM
                                     );
  die_if_ssl_error("private key");
  Net::SSLeay::use_certificate_file( $ssl,
                                     $cert,
                                     &Net::SSLeay::FILETYPE_PEM
                                   );
  die_if_ssl_error("certificate");

  my $accepted = 0;
  my $resp = Net::SSLeay::accept($ssl);
  if ($resp <= 0) { # 0 is really controlled shutdown but we signal error
    my $errno = Net::SSLeay::get_error($ssl, $resp);
    if ($errno == ERROR_WANT_READ or $errno == ERROR_WANT_WRITE) {
      # we try again next time in READ
    }
    else {
      # handshake failed
      return undef;
    }
  }
  else {
    $accepted = 1;
  }

  $class->_set_filenum_obj($fileno, $ssl, $ctx, $socket, $accepted);

  return bless $socket, $class;
}

1;

__END__

=head1 NAME

POE::Component::Client::HTTP::SSL - non-blocking SSL file handles

=head1 SYNOPSIS

  See Net::SSLeay::Handle

=head1 DESCRIPTION

This is a temporary subclass of Net::SSLeay::Handle with what I
consider proper read() and sysread() semantics.  This module will go
away if or when Net::SSLeay::Handle adopts these semantics.

POE::Component::Client::HTTP::SSL functions identically to
Net::SSLeay::Handle, but the READ function does not block until LENGTH
bytes are read.

=head1 SEE ALSO

Net::SSLeay::Handle

=head1 BUGS

None known.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::HTTP::SSL is Copyright 1999-2002 by Rocco
Caputo.  All rights are reserved.  This module is free software; you
may redistribute it and/or modify it under the same terms as Perl
itself.

Rocco may be contacted by e-mail via rcaputo@cpan.org.

=cut
