#!/usr/bin/env perl
package Plack::Middleware::Validate_Google_IAP_JWT;
use strict;
use warnings;

our $VERSION = "0.01";

use MOP4Import::Base::CLI_JSON -as_base
  , [fields =>
     , [key_url => default => "https://www.gstatic.com/iap/verify/public_key-jwk"]
     , [want_iss => default => "https://cloud.google.com/iap"],
     , [want_hd => doc => "expected hosting domain"],
     , qw(
       app
       _iap_public_key
       _expires_at
     )
   ]
  ;

use parent qw(Plack::Middleware);

use File::Basename;
use Time::Piece;

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
  )]],
  Response => [[fields => qw(
    success
    url
    status
    reason
    content
    headers
    protocol
    redirects
  )]],
  ResHeaders => [[fields => qw(
      accept-ranges
      cache-control
      content-length
      content-security-policy
      content-type
      cross-origin-opener-policy
      cross-origin-resource-policy
      date
      expires
      last-modified
      report-to
      server
      vary
      x-content-type-options
      x-xss-protection
  )]]
  ;

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
  if ($self->{_iap_public_key} and (time + 10) < $self->{_expires_at}) {
    return $self->{_iap_public_key}
  }
  my ($ok, $err) = $self->fetch_iap_public_key_with_expires;
  if ($err) {
    Carp::croak "Can't fetch iap public_key: $err";
  }

  ($self->{_iap_public_key}, $self->{_expires_at}) = @$ok;

  return $self->{_iap_public_key};
}

sub fetch_iap_public_key {
  (my MY $self) = @_;
  my ($ok, $err) = $self->fetch_iap_public_key_with_expires;
  if ($err) {
    return (undef, $err)
  } else {
    $ok->[0]
  }
}

sub fetch_iap_public_key_with_expires {
  (my MY $self) = @_;
  my Response $response = HTTP::Tiny->new->request(GET => $self->{key_url});
  if ($response->{success}) {
    my $jwt = $self->cli_decode_json($response->{content});
    my ResHeaders $headers = $response->{headers};
    my $expires = $headers->{expires} ? $self->parse_http_date($headers->{expires}) : undef;
    [$jwt, $expires];
  } else {
    (undef, $response->{reason})
  }
}

sub parse_http_date {
  (my MY $self, my $date) = @_;
  Time::Piece->strptime($date, "%a, %d %b %Y %H:%M:%S %Z")->epoch
}

MY->run(\@ARGV) unless caller;
1;
__END__

=encoding utf-8

=head1 NAME

Plack::Middleware::Validate_Google_IAP_JWT - Validate JWT given from Google IAP

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

Plack::Middleware::Validate_Google_IAP_JWT is ...

=head1 LICENSE

Copyright (C) Kobayasi, Hiroaki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Kobayasi, Hiroaki E<lt>buribullet@gmail.comE<gt>

=cut

