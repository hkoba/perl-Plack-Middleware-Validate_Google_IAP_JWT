#!/usr/bin/env perl
package Plack::Middleware::Validate_Google_IAP_JWT;
use strict;
use warnings;

our $VERSION = "0.01";

use MOP4Import::Base::CLI_JSON -as_base
  , [fields =>
     , [cache_file => default => "var/cache/public_key-jwk.json"]
     , [key_url => default => "https://www.gstatic.com/iap/verify/public_key-jwk"]
     , [want_iss => default => "https://cloud.google.com/iap"],
     , [want_hd => doc => "expected hosting domain"],
     , qw(
       app
       _iap_public_key
     )
   ]
  ;

use parent qw(Plack::Middleware);

use File::Basename;

use URI;
use HTTP::Tiny;

use Crypt::JWT ();

use MOP4Import::PSGIEnv qw(
  HTTP_X_GOOG_IAP_JWT_ASSERTION
  psgix.goog_iap_jwt
  psgix.goog_iap_jwt_aud
  psgix.goog_iap_jwt_email
  psgix.goog_iap_jwt_sub
  psgix.goog_iap_jwt_account
);

use MOP4Import::Types
  JWT => [[fields => qw(
    aud email sub
  )]];

sub call {
  (my MY $self, my Env $env) = @_;

  my JWT $jwt = $self->decode_jwt_env($env);
  $env->{'psgix.goog_iap_jwt'}       = $jwt;
  $env->{'psgix.goog_iap_jwt_aud'}   = $jwt->{aud};
  $env->{'psgix.goog_iap_jwt_email'} = $jwt->{email};
  $env->{'psgix.goog_iap_jwt_sub'}   = $jwt->{sub};
  if ($self->{want_hd}) {
    (my $account = $jwt->{email}) =~ s,@\Q$self->{want_hd}\E\z,,;
    $env->{'psgix.goog_iap_jwt_account'} = $account;
  }

  $self->app->($env)
}

sub decode_jwt_env {
  (my MY $self, my Env $env) = @_;
  Crypt::JWT::decode_jwt(
    token => $env->{HTTP_X_GOOG_IAP_JWT_ASSERTION},
    kid_keys => $self->iap_public_key,
    verify_exp => 1, verify_iat => 1,
    verify_iss => $self->{want_iss},
    ($self->{want_hd} ? (verify_hd => $self->{want_hd}) : ()),
  )
}

sub iap_public_key {
  (my MY $self) = @_;
  $self->{_iap_public_key} //= do {
    if (-e $self->{cache_file}) {
      $self->cli_read_file($self->{cache_file});
    } else {
      my ($ok, $err) = $self->fetch_iap_public_key;
      unless (-e (my $dir = dirname($self->{cache_file}))) {
        mkdir $dir or die "Can't mkdir $dir: $!";
      }
      open my $fh, '>', $self->{cache_file}
        or Carp::croak "Can't write to $self->{cache_file}: $!";
      print $fh $self->cli_encode_json($ok);
      $ok;
    }
  };
}

sub fetch_iap_public_key {
  (my MY $self) = @_;
  my $response = HTTP::Tiny->new->request(GET => $self->{key_url});
  if ($response->{success}) {
    $self->cli_decode_json($response->{content})
  } else {
    (undef, $response->{reason})
  }
}

MY->run(\@ARGV) unless caller;
1;
__END__

=encoding utf-8

=head1 NAME

Plack::Middleware::Validate_Google_IAP_JWT - Validate JWT from Google IAP

=head1 SYNOPSIS

  use Plack::Builder;

  my $app = sub {
    my $env = shift;
    return [200, [], ["Validated email: ", $env->{"psgix.goog_iap_jwt_email"}]]
  };

  builder {
    enable "Validate_Google_IAP_JWT", want_hd => "example.com";
    $app;
  };

=head1 DESCRIPTION

Plack::Middleware::Validate_Google_IAP_JWT is a Plack middleware that validates JWT from
L<Google Cloud Identity-Aware Proxy(IAP)|https://cloud.google.com/security/products/iap>. 
Although Cloud IAP rejects unauthorized access from public networks, 
internal processes on the same network can still spoof the identity.
To protect against such security risks, Cloud IAP provides a special HTTP header, L<'x-goog-iap-jwt-assertion'|https://cloud.google.com/iap/docs/signed-headers-howto>,
which carries JWT containing the email address of the authenticated end user.
 This middleware protects Plack apps by validating the JWT.

=head1 CONFIGURATION

=head2 want_hd

Expected hosted domain. See L<https://cloud.google.com/iap/docs/signed-headers-howto#verifying_the_jwt_payload>.

=head1 METHODS

=head2 fetch_iap_public_key

=head1 LICENSE

Copyright (C) Kobayasi, Hiroaki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Kobayasi, Hiroaki E<lt>buribullet@gmail.comE<gt>

=cut
