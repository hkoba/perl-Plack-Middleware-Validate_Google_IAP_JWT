#!/usr/bin/env perl
package Google_IAP_JWT_Check;
use strict;
use warnings;
use MOP4Import::Base::CLI_JSON -as_base
  , [fields =>
     , [cache_file => default => "var/cache/public_key-jwk.json"]
     , [key_url => default => "https://www.gstatic.com/iap/verify/public_key-jwk"]
     , qw(
       _iap_public_key
     )
   ]
  ;

use File::Basename;

use URI;
use HTTP::Tiny;

use Crypt::JWT ();

use MOP4Import::PSGIEnv qw(
  HTTP_X_GOOG_IAP_JWT_ASSERTION
);

sub decode_jwt_env {
  (my MY $self, my Env $env) = @_;
  Crypt::JWT::decode_jwt(
    token => $env->{HTTP_X_GOOG_IAP_JWT_ASSERTION},
    kid_keys => $self->iap_public_key
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
