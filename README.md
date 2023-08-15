
# NAME

Plack::Middleware::Validate\_Google\_IAP\_JWT - Validate JWT given from Google IAP

# SYNOPSIS

    use Plack::Builder;

    my $app = sub {
      my $env = shift;
      return [200, [], ["Validated email: ", $env->{"psgix.goog_iap_jwt_email"}]]
    };

    builder {
      enable "Validate_Google_IAP_JWT", want_hd => "example.com";
      $app;
    };

# DESCRIPTION

Plack::Middleware::Validate\_Google\_IAP\_JWT is ...

# LICENSE

Copyright (C) Kobayasi, Hiroaki.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

Kobayasi, Hiroaki <buribullet@gmail.com>
