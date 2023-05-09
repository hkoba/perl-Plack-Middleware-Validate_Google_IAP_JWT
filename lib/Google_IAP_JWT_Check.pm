#!/usr/bin/env perl
package Google_IAP_JWT_Check;
use strict;
use warnings;
use MOP4Import::Base::CLI_JSON -as_base
  , [fields =>
     , [cache_dir => default => "var/cache"]
     , [cache_file => default => "public_key-jwk.json"]
     , [key_url => default => "https://www.gstatic.com/iap/verify/public_key-jwk"]
   ]
  ;

use URI;
use HTTP::Tiny;

sub fetch_public_key {
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
