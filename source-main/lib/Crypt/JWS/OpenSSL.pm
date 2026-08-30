package Crypt::JWS::OpenSSL;
$Crypt::JWS::OpenSSL::VERSION = '0.001';
use Moo 2.004003;
with qw( Crypt::JWS::OpenSSL::Role::Encoder );
use Crypt::JWS::OpenSSL::Algorithm::RSA;
use Crypt::JWS::OpenSSL::Algorithm::ECC;
use Crypt::JWS::OpenSSL::Algorithm::HMAC;
use Try::Tiny;
use Digest::SHA;
use Carp qw(croak confess);
use namespace::clean;

my $ALGO_MAP = {
    'HS256' => [ 'hmac_handler', undef,                      [  43 ,   43 ] ],
    'HS384' => [ 'hmac_handler', undef,                      [  64 ,   64 ] ],
    'HS512' => [ 'hmac_handler', undef,                      [  86 ,   86 ] ],
    'RS256' => [ 'rsa_handler', 'can_use_pkcs1_padding',     [ 171 ,  683 ] ],
    'RS384' => [ 'rsa_handler', 'can_use_pkcs1_padding',     [ 171 ,  683 ] ],
    'RS512' => [ 'rsa_handler', 'can_use_pkcs1_padding',     [ 171 ,  683 ] ],
    'PS256' => [ 'rsa_handler', 'can_use_pkcs1_pss_padding', [ 171 ,  683 ] ],
    'PS384' => [ 'rsa_handler', 'can_use_pkcs1_pss_padding', [ 171 ,  683 ] ],
    'PS512' => [ 'rsa_handler', 'can_use_pkcs1_pss_padding', [ 171 ,  683 ] ],
    'ES256' => [ 'ecc_handler',  undef,                      [  86 ,   86 ] ],
    'ES384' => [ 'ecc_handler',  undef,                      [ 128 ,  128 ] ],
    'ES512' => [ 'ecc_handler',  undef,                      [ 176 ,  176 ] ],
};

has 'hmac_handler' => ( is => 'lazy');
has 'rsa_handler'  => ( is => 'lazy');
has 'ecc_handler'  => ( is => 'lazy');
has 'last_error'   => ( is => 'rwp', default => '' );
has 'throw_errors' => ( is => 'rw',  default => 0  );

sub encode {
    my($self, $params ) = parse_params(@_);
    $self->_set_last_error('');
    unless(defined($params->{'secret'})
           && ( length($params->{'secret'}) >= 32
               || ref($params->{'secret'}) eq 'HASH')
          ){
        $self->_set_last_error('Missing or invalid secret for signing');
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
    my $header = $params->{'header'};
    unless($header && ref($header) eq 'HASH') {
        $self->_set_last_error('Missing or invalid header argument');
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
    
    my $input_alg = uc($header->{alg} || 'MISSING');
    
    my $handler = $self->_supported_algorithm($input_alg);
    
    unless( $handler ) {
        $self->_set_last_error(qq(Algorithm "$input_alg" is not supported));
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
    
    my $claims = $params->{claims};
    unless($claims && ref($claims) eq 'HASH' && scalar( keys %$claims  ) ) {
        $self->_set_last_error('Missing or invalid claims argument');
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
           
    $header->{alg} = $input_alg;
    $header->{typ} ||= 'JWT';
    
    my $d_flag = ( $params->{non_deterministic} ) ? 1 : 0;
    
    my $header_segment  = $self->encode_jwt_segment($header);
    my $claims_segment  = $self->encode_jwt_segment($claims);
    my $signature_input = join '.', $header_segment, $claims_segment;
    my $signature = try {
        $self->$handler->sign(
            {
                algorithm         => $input_alg,
                message           => $signature_input,
                key               => $params->{'secret'},
                non_deterministic => $d_flag
            }
        );
    } catch {
        my $error = $self->_clean_handler_error( $_ );
        $self->_set_last_error('Error signing token : ' . $error);
        croak($self->last_error) if $self->throw_errors;
        return undef;
    };
    
    if (defined($signature)) {
        return join '.', $signature_input, $self->encode_jwt_signature($signature);
    } else {
        return undef;
    }
}

sub decode_unverified {
    my($self, $params) = parse_params(@_);
    
    $self->_set_last_error('');
    
    my $return = {
        header      => undef,
        claims      => undef,
        verifytoken => undef,
        error       => undef,
    };
    unless($params->{token}) {
        my $errstring = 'Missing token argument';
        $self->_set_last_error($errstring);
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
    
    my $segments = [ split '\.', $params->{token} ];
    {
        my $segcount = @$segments;
        unless($segcount == 3) {
            my $errstring = "Invalid number of segments( $segcount ) in token";
            $self->_set_last_error($errstring);
            croak($self->last_error) if $self->throw_errors;
            return undef;
        }
    }
    
    my ($header_segment, $claims_segment, $crypto_segment) = @$segments;
    my ($header, $claims);
    my $caughterror = try {
        $header   = $self->decode_jwt_segment($header_segment);
        $claims   = $self->decode_jwt_segment($claims_segment);
        return 0;
    } catch {
        my $errstring = 'Error decoding token : ' . $self->_clean_handler_error( $_ );
        $self->_set_last_error($errstring);
        croak($self->last_error) if $self->throw_errors;
        return 1;
    };
    
    return undef if $caughterror;
    
    $return->{claims} = $claims;
    $return->{header} = $header;
    
    my $algo = 'NONE';
    
    if ( ref($header) eq 'HASH' && exists($header->{alg}) ) {
        $algo = uc($header->{alg} || 'NONE' );
    }
    
    my $signature_input = join('.', $header_segment, $claims_segment );
    
    my $verifytoken = join(':', $algo, $signature_input, $crypto_segment );
    $return->{verifytoken} = $verifytoken;
    return $return;
}

sub verify {
    my($self, $params) = parse_params(@_);
    
    $self->_set_last_error('');
    
    unless(defined($params->{'secret'})
           && ( length($params->{'secret'}) >= 32
               || ref($params->{'secret'}) eq 'HASH')
          ){
        $self->_set_last_error('Missing or invalid secret for signing');
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
    
    unless($params->{verifytoken}) {
        $self->_set_last_error('No verifytoken provided');
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
        
    my $segments = [ split ':', $params->{verifytoken} ];
    
    {
        my $segcount = @$segments;
        unless($segcount == 3) {
            $self->_set_last_error("Invalid number of segments($segcount) in verifytoken");
            croak($self->last_error) if $self->throw_errors;
            return undef;
        }
    }
    
    my( $input_algorithm, $signature_input, $crypto_segment ) = @$segments;
    
    my ( $signature );
    try {
        $signature = $self->decode_jwt_signature($crypto_segment);
    } catch {
        my $error = $self->_clean_handler_error( $_ );
        $self->_set_last_error("Invalid verifytoken");
        croak($self->last_error) if $self->throw_errors;
        return undef
    };
        
    my $handler = $self->_supported_algorithm($input_algorithm);
            
    unless( $handler ) {
        $self->_set_last_error(qq(header algorithm "$input_algorithm" is not supported));
        croak($self->last_error) if $self->throw_errors;
        return undef;
    }
    
    my $verified = try {
        $self->$handler->verify({
            algorithm => $input_algorithm,
            message   => $signature_input,
            key       => $params->{secret},
            signature => $signature
        });
    } catch {
        my $error = $self->_clean_handler_error( $_ );
        $self->_set_last_error('Error verifying token : ' . $error);
        croak($self->last_error) if $self->throw_errors;
        return undef;
    };
    
    return ( $verified && $verified eq '1' ) ? 1 : 0;
}

sub can_use_pkcs1_padding {
    return shift->rsa_handler->can_use_pkcs1_padding;
}

sub can_use_pkcs1_pss_padding {
    return shift->rsa_handler->can_use_pkcs1_pss_padding;
}

sub can_do_non_deterministic {
    return shift->ecc_handler->can_do_non_deterministic;
}

sub can_do_deterministic {
    return shift->ecc_handler->can_do_deterministic;
}

sub _supported_algorithm {
    my($self, $algo) = @_;
    return undef unless( $algo );
    if ( exists($ALGO_MAP->{$algo}) ) {
        my $handler = $ALGO_MAP->{$algo}->[0];
        my $check   = $ALGO_MAP->{$algo}->[1];
        if ( $check ) {
            return ( $self->$handler->$check ) ? $handler : undef; 
        } else {
            return $handler;
        }
    } else {
        return undef;
    }
}

sub _valid_signature_length {
    my($self, $algo, $length) = @_;
    return 0 unless($algo && $length && $length =~ m!^[1-9][0-9]{1,3}$!);
    if (exists($ALGO_MAP->{$algo})) {
        my( $min, $max ) = @{ $ALGO_MAP->{$algo}->[2] };
        return ( $length >= $min && $length <= $max ) ? 1 : 0;
    }
    return 0;
}

sub _clean_handler_error {
    my( $self, $error ) = @_;
    $error ||= 'unknown error';
    my ($clean_error) = $error =~ m!^([\x00-\x7F]*)!;
    $clean_error ||= 'unknown error';
    my ($report_error) = split(/[\n\r]+/, $clean_error);
    $report_error =~ s! at .+ line [0-9]+\.$!!;
    return $report_error;
}

sub _build_hmac_handler {
    return Crypt::JWS::OpenSSL::Algorithm::HMAC->new;
}

sub _build_rsa_handler {
    return Crypt::JWS::OpenSSL::Algorithm::RSA->new;
}

sub _build_ecc_handler {
    return Crypt::JWS::OpenSSL::Algorithm::ECC->new;
}

# ABSTRACT: Encode, decode and verify signed compact JWTs using OpenSSL modules

1;

__END__

=pod

=encoding UTF-8

=head1 NAME

Crypt::JWS::OpenSSL - Encode, decode and verify signed compact JWTs using OpenSSL modules

=head1 VERSION

version 0.001

=head1 SYNOPSYS

  use Crypt::JWS::OpenSSL;
  my $cjos = Crypt::JWS::OpenSSL->new;
  
  my $token = $cjos->encode(
      header => $header_ref,
      claims => $claims_ref,
      secret => $key,
  );
  
  my $unverified = $cjos->decode_unverified($inboundtoken);
  
  my $secret = local_method_to_choose_secret(
      $unverified->{header}, $unverified->{claims}
  );
  
  die 'I do not know the sender' if(!$secret);
  
  my $ok = $cjos->verify(
    secret      => $secret,
    verifytoken => $unverified->{verifytoken}
  );

  if( !$ok ) {
    die 'I do not trust this token';
  }


=head1 AUTHOR

Mark Dootson E<lt>mdootson@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2026 by Mark Dootson

This library is free software; you can redistribute it and/or modify
it under the same terms as the Perl 5 programming language system itself.

=cut
