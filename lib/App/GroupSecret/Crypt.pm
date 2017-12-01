package App::GroupSecret::Crypt;
# ABSTRACT: Collection of crypto-related subroutines

use warnings;
use strict;

our $VERSION = '9999.999'; # VERSION

use Exporter qw(import);
use File::Temp;
use IPC::Open2;
use namespace::clean -except => [qw(import)];

our @EXPORT_OK = qw(
    generate_secure_random_bytes
    read_openssh_public_key
    read_openssh_key_fingerprint
    decrypt_rsa
    encrypt_rsa
    decrypt_aes_256_cbc
    encrypt_aes_256_cbc
);

sub _croak { require Carp; Carp::croak(@_) }
sub _usage { _croak("Usage: @_\n") }

=func generate_secure_random_bytes

    $bytes = generate_secure_random_bytes($num_bytes);

Get a certain number of secure random bytes.

=cut

sub generate_secure_random_bytes {
    my $size = shift or _usage(q{generate_secure_random_bytes($num_bytes)});

    my @cmd = (qw{openssl rand}, $size);

    my ($in, $out);
    my $pid = open2($out, $in, @cmd);

    close($in);
    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to generate secure random bytes' if $exit_code != 0;

    return do { local $/; <$out> };
}

=func read_openssh_public_key

    $pem_public_key = read_openssh_public_key($public_key_filepath);

Read a RFC4716 (SSH2) public key from a file, converting it to PKCS8 (PEM).

=cut

sub read_openssh_public_key {
    my $filepath = shift or _usage(q{read_openssh_public_key($filepath)});

    my @cmd = (qw{ssh-keygen -e -m PKCS8 -f}, $filepath);

    my ($in, $out);
    my $pid = open2($out, $in, @cmd);

    close($in);

    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to read OpenSSH public key' if $exit_code != 0;

    return do { local $/; <$out> };
}

=func read_openssh_key_fingerprint

    $fingerprint = read_openssh_key_fingerprint($filepath);

Get the fingerprint of an OpenSSH private or public key.

=cut

sub read_openssh_key_fingerprint {
    my $filepath = shift or _usage(q{read_openssh_key_fingerprint($filepath)});

    my @cmd = (qw{ssh-keygen -l -E md5 -f}, $filepath);

    my $out;
    my $pid = open2($out, undef, @cmd);

    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to read SSH2 key fingerprint' if $exit_code != 0;

    my $line = do { local $/; <$out> };
    chomp $line;

    my ($bits, $fingerprint, $comment, $type) = $line =~ m!^(\d+) MD5:([^ ]+) (.*) \(([^\)]+)\)$!;

    $fingerprint =~ s/://g;

    return {
        bits        => $bits,
        fingerprint => $fingerprint,
        comment     => $comment,
        type        => lc($type),
    };
}

=func decrypt_rsa

    $plaintext = decrypt_rsa($ciphertext_filepath, $private_key_filepath);
    $plaintext = decrypt_rsa(\$ciphertext, $private_key_filepath);
    decrypt_rsa($ciphertext_filepath, $private_key_filepath, $plaintext_filepath);
    decrypt_rsa(\$ciphertext, $private_key_filepath, $plaintext_filepath);

Do RSA decryption. Turn ciphertext into plaintext.

=cut

sub decrypt_rsa {
    my $filepath = shift or _usage(q{decrypt_rsa($filepath, $keypath)});
    my $privkey  = shift or _usage(q{decrypt_rsa($filepath, $keypath)});
    my $outfile  = shift;

    my $temp;
    if (ref $filepath eq 'SCALAR') {
        $temp = File::Temp->new(UNLINK => 1);
        print $temp $$filepath;
        close $temp;
        $filepath = $temp->filename;
    }

    my @cmd = (qw{openssl rsautl -decrypt -oaep -in}, $filepath, '-inkey', $privkey);
    push @cmd, ('-out', $outfile) if $outfile;

    my ($in, $out);
    my $pid = open2($out, $in, @cmd);

    close($in);

    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to decrypt ciphertext' if $exit_code != 0;

    return do { local $/; <$out> };
}

=func encrypt_rsa

    $ciphertext = decrypt_rsa($plaintext_filepath, $public_key_filepath);
    $ciphertext = decrypt_rsa(\$plaintext, $public_key_filepath);
    decrypt_rsa($plaintext_filepath, $public_key_filepath, $ciphertext_filepath);
    decrypt_rsa(\$plaintext, $public_key_filepath, $ciphertext_filepath);

Do RSA encryption. Turn plaintext into ciphertext.

=cut

sub encrypt_rsa {
    my $filepath = shift or _usage(q{encrypt_rsa($filepath, $keypath)});
    my $pubkey   = shift or _usage(q{encrypt_rsa($filepath, $keypath)});
    my $outfile  = shift;

    my $temp1;
    if (ref $filepath eq 'SCALAR') {
        $temp1 = File::Temp->new(UNLINK => 1);
        print $temp1 $$filepath;
        close $temp1;
        $filepath = $temp1->filename;
    }

    my $key = read_openssh_public_key($pubkey);

    my $temp2 = File::Temp->new(UNLINK => 1);
    print $temp2 $key;
    close $temp2;
    my $keypath = $temp2->filename;

    my @cmd = (qw{openssl rsautl -encrypt -oaep -pubin -inkey}, $keypath, '-in', $filepath);
    push @cmd, ('-out', $outfile) if $outfile;

    my ($in, $out);
    my $pid = open2($out, $in, @cmd);

    close($in);

    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to encrypt plaintext' if $exit_code != 0;

    return do { local $/; <$out> };
}

=func decrypt_aes_256_cbc

    $plaintext = decrypt_aes_256_cbc($ciphertext_filepath, $secret);
    $plaintext = decrypt_aes_256_cbc(\$ciphertext, $secret);
    decrypt_aes_256_cbc($ciphertext_filepath, $secret, $plaintext_filepath);
    decrypt_aes_256_cbc(\$ciphertext, $secret, $plaintext_filepath);

Do symmetric decryption. Turn ciphertext into plaintext.

=cut

sub decrypt_aes_256_cbc {
    my $filepath = shift or _usage(q{decrypt_aes_256_cbc($ciphertext, $secret)});
    my $secret   = shift or _usage(q{decrypt_aes_256_cbc($ciphertext, $secret)});
    my $outfile  = shift;

    my $temp;
    if (ref $filepath eq 'SCALAR') {
        $temp = File::Temp->new(UNLINK => 1);
        print $temp $$filepath;
        close $temp;
        $filepath = $temp->filename;
    }

    my @cmd = (qw{openssl aes-256-cbc -d -pass stdin -md sha256 -in}, $filepath);
    push @cmd, ('-out', $outfile) if $outfile;

    my ($in, $out);
    my $pid = open2($out, $in, @cmd);

    print $in $secret;
    close($in);

    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to decrypt ciphertext' if $exit_code != 0;

    return do { local $/; <$out> };
}

=func encrypt_aes_256_cbc

    $ciphertext = encrypt_aes_256_cbc($plaintext_filepath, $secret);
    $ciphertext = encrypt_aes_256_cbc(\$plaintext, $secret);
    encrypt_aes_256_cbc($plaintext_filepath, $secret, $ciphertext_filepath);
    encrypt_aes_256_cbc(\$plaintext, $secret, $ciphertext_filepath);

Do symmetric encryption. Turn plaintext into ciphertext.

=cut

sub encrypt_aes_256_cbc {
    my $filepath = shift or _usage(q{encrypt_aes_256_cbc($plaintext, $secret)});
    my $secret   = shift or _usage(q{encrypt_aes_256_cbc($plaintext, $secret)});
    my $outfile  = shift;

    my $temp;
    if (ref $filepath eq 'SCALAR') {
        $temp = File::Temp->new(UNLINK => 1);
        print $temp $$filepath;
        close $temp;
        $filepath = $temp->filename;
    }

    my @cmd = (qw{openssl aes-256-cbc -pass stdin -md sha256 -in}, $filepath);
    push @cmd, ('-out', $outfile) if $outfile;

    my ($in, $out);
    my $pid = open2($out, $in, @cmd);

    print $in $secret;
    close($in);

    waitpid($pid, 0);
    my $status = $?;

    my $exit_code = $status >> 8;
    _croak 'Failed to encrypt plaintext' if $exit_code != 0;

    return do { local $/; <$out> };
}

1;
