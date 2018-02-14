package App::GroupSecret::File;
# ABSTRACT: Reading and writing groupsecret keyfiles

=head1 SYNOPSIS

    use App::GroupSecret::File;

    my $file = App::GroupSecret::File->new('path/to/keyfile.yml');
    print "File version: " . $file->version, "\n";

    $file->add_key('path/to/key_rsa.pub');
    $file->save;

=head1 DESCRIPTION

This module provides a programmatic way to manage keyfiles.

See L<groupsecret> for the command-line interface.

=head1 FILE FORMAT

Keyfiles are YAML documents that contains this structure:

    ---
    keys:
      FINGERPRINT:
        comment: COMMENT
        content: ssh-rsa ...
        filename: FILENAME
        secret_passphrase: PASSPHRASE...
        type: rsa
    secret: SECRET...
    version: 1

=cut

use warnings;
use strict;

our $VERSION = '9999.999'; # VERSION

use App::GroupSecret::Crypt qw(
    generate_secure_random_bytes
    read_openssh_public_key
    read_openssh_key_fingerprint
    decrypt_rsa
    encrypt_rsa
    decrypt_aes_256_cbc
    encrypt_aes_256_cbc
);
use File::Basename;
use File::Spec;
use YAML::Tiny qw(LoadFile DumpFile);
use namespace::clean;

our $FILE_VERSION = 1;

sub _croak { require Carp; Carp::croak(@_) }
sub _usage { _croak("Usage: @_\n") }

=method new

    $file = App::GroupSecret::File->new($filepath);

Construct a new keyfile object.

=cut

sub new {
    my $class = shift;
    my $filepath = shift or _croak(q{App::GroupSecret::File->new($filepath)});
    return bless {filepath => $filepath}, $class;
}

=attr filepath

Get the filepath of the keyfile.

=cut

sub filepath { shift->{filepath} }

=method info

    $info = $file->info;

Get a raw hashref with the contents of the keyfile.

=cut

sub info {
    my $self = shift;
    return $self->{info} ||= do {
        if (-e $self->filepath) {
            $self->load;
        }
        else {
            $self->init;
        }
    };
}

=method init

    $info = $file->init;

Get a hashref representing an empty keyfile, used for initializing a new keyfile.

=cut

sub init {
    return {
        keys    => {},
        secret  => undef,
        version => $FILE_VERSION,
    };
}

=method load

    $info = $file->load;
    $info = $file->load($filepath);

Load (or reload) the contents of a keyfile.

=cut

sub load {
    my $self     = shift;
    my $filepath = shift || $self->filepath;
    my $info = LoadFile($filepath) || {};
    $self->check($info);
    $self->{info} = $info if !$filepath;
    return $info;
}

=method save

    $file->save;
    $file->save($filepath);

Save the keyfile to disk.

=cut

sub save {
    my $self     = shift;
    my $filepath = shift || $self->filepath;
    DumpFile($filepath, $self->info);
    return $self;
}

=method check

    $file->check;
    $file->check($info);

Check the file format of a keyfile to make sure this module can understand it.

=cut

sub check {
    my $self = shift;
    my $info = shift || $self->info;

    _croak 'Corrupt file: Bad type for root' if !$info || ref $info ne 'HASH';

    my $version = $info->{version};
    _croak 'Unknown file version' if !$version || $version !~ /^\d+$/;
    _croak 'Unsupported file version' if $FILE_VERSION < $version;

    _croak 'Corrupt file: Bad type for keys' if ref $info->{keys} ne 'HASH';

    warn "The file has a secret but no keys to access it!\n" if $info->{secret} && !%{$info->{keys}};

    return 1;
}

=method keys

    $keys = $file->keys;

Get a hashref of the keys from a keyfile.

=method secret

    $secret = $file->secret;

Get the secret from a keyfile as an encrypted string.

=method version

    $version = $file->version

Get the file format version.

=cut

sub keys    { shift->info->{keys} }
sub secret  { shift->info->{secret} }
sub version { shift->info->{version} }

=method add_key

    $file->add_key($filepath);

Add a key to the keyfile.

=cut

sub add_key {
    my $self        = shift;
    my $public_key  = shift or _usage(q{$file->add_key($public_key)});
    my $args        = @_ == 1 ? shift : {@_};

    my $keys = $self->keys;

    my $info = $args->{fingerprint_info} || read_openssh_key_fingerprint($public_key);
    my $fingerprint = $info->{fingerprint};

    my $key = {
        comment             => $info->{comment},
        filename            => basename($public_key),
        secret_passphrase   => undef,
        type                => $info->{type},
    };

    if ($args->{embed}) {
        open(my $fh, '<', $public_key) or die "open failed: $!";
        $key->{content} = do { local $/; <$fh> };
        chomp $key->{content};
    }

    $keys->{$fingerprint} = $key;

    if ($self->secret) {
        my $passphrase = $args->{passphrase} || $self->decrypt_secret_passphrase($args->{private_key});
        my $ciphertext = encrypt_rsa(\$passphrase, $public_key);
        $key->{secret_passphrase} = $ciphertext;
    }

    return wantarray ? ($fingerprint => $key) : $key;
}

=method delete_key

    $file->delete_key($fingerprint);

Delete a key from the keyfile.

=cut

sub delete_key {
    my $self        = shift;
    my $fingerprint = shift;
    delete $self->keys->{$fingerprint};
}

=method decrypt_secret

    $secret = $file->decrypt_secret(passphrase => $passphrase);
    $secret = $file->decrypt_secret(private_key => $private_key);

Get the decrypted secret.

=cut

sub decrypt_secret {
    my $self = shift;
    my $args = @_ == 1 ? shift : {@_};

    $args->{passphrase} || $args->{private_key} or _usage(q{$file->decrypt_secret($private_key)});

    my $passphrase = $args->{passphrase};
    $passphrase = $self->decrypt_secret_passphrase($args->{private_key}) if !$passphrase;

    my $ciphertext = $self->secret;
    return decrypt_aes_256_cbc(\$ciphertext, $passphrase);
}

=method decrypt_secret_passphrase

    $passphrase = $file->decrypt_secret_passphrase($private_key);

Get the decrypted secret passphrase.

=cut

sub decrypt_secret_passphrase {
    my $self        = shift;
    my $private_key = shift or _usage(q{$file->decrypt_secret_passphrase($private_key)});

    die "Private key '$private_key' not found.\n" unless -e $private_key && !-d $private_key;

    my $info = read_openssh_key_fingerprint($private_key);
    my $fingerprint = $info->{fingerprint};

    my $keys = $self->keys;
    if (my $key = $keys->{$fingerprint}) {
        return decrypt_rsa(\$key->{secret_passphrase}, $private_key);
    }

    die "Private key '$private_key' not able to decrypt the keyfile.\n";
}

=method encrypt_secret

    $file->encrypt_secret($secret, $passphrase);

Set the secret by encrypting it with a 256-bit passphrase.

Passphrase must be 32 bytes.

=cut

sub encrypt_secret {
    my $self        = shift;
    my $secret      = shift or _usage(q{$file->encrypt_secret($secret)});
    my $passphrase  = shift or _usage(q{$file->encrypt_secret($secret)});

    my $ciphertext = encrypt_aes_256_cbc($secret, $passphrase);
    $self->info->{secret} = $ciphertext;
}

=method encrypt_secret_passphrase

    $file->encrypt_secret_passphrase($passphrase);

Set the passphrase by encrypting it with each key in the keyfile.

=cut

sub encrypt_secret_passphrase {
    my $self        = shift;
    my $passphrase  = shift or _usage(q{$file->encrypt_secret_passphrase($passphrase)});

    while (my ($fingerprint, $key) = each %{$self->keys}) {
        local $key->{fingerprint} = $fingerprint;
        my $pubkey = $self->find_public_key($key) or die 'Cannot find public key: ' . $self->format_key($key) . "\n";
        my $ciphertext = encrypt_rsa(\$passphrase, $pubkey);
        $key->{secret_passphrase} = $ciphertext;
    }
}

=method find_public_key

    $filepath = $file->find_public_key($key);

Get a path to the public key file for a key.

=cut

sub find_public_key {
    my $self = shift;
    my $key  = shift or _usage(q{$file->find_public_key($key)});

    if ($key->{content}) {
        my $temp = File::Temp->new(UNLINK => 1);
        print $temp $key->{content};
        close $temp;
        $self->{"temp:$key->{fingerprint}"} = $temp;
        return $temp->filename;
    }
    else {
        my @dirs = split(/:/, $ENV{GROUPSECRET_PATH} || ".:keys:$ENV{HOME}/.ssh");
        for my $dir (@dirs) {
            my $filepath = File::Spec->catfile($dir, $key->{filename});
            return $filepath if -e $filepath && !-d $filepath;
        }
    }
}

=method format_key

    $str = $file->format_key($key);

Get a one-line summary of a key. Format is "<fingerprint> <comment>".

=cut

sub format_key {
    my $self = shift;
    my $key  = shift or _usage(q{$file->format_key($key)});

    my $fingerprint = $key->{fingerprint} or _croak(q{Missing required field in key: fingerprint});
    my $comment     = $key->{comment} || 'uncommented';

    if ($fingerprint =~ /^[A-Fa-f0-9]{32}$/) {
        $fingerprint = 'MD5:' . join(':', ($fingerprint =~ /../g ));
    }
    elsif ($fingerprint =~ /^[A-Za-z0-9\/\+]{27}$/) {
        $fingerprint = "SHA1:$fingerprint";
    }
    elsif ($fingerprint =~ /^[A-Za-z0-9\/\+]{43}$/) {
        $fingerprint = "SHA256:$fingerprint";
    }

    return "$fingerprint $comment";
}

1;
