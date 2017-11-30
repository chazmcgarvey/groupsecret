# NAME

App::GroupSecret - A simple tool for maintaining a shared group secret

# VERSION

version 0.300

# DESCRIPTION

This module is part of the command-line interface for managing keyfiles.

See [groupsecret](https://metacpan.org/pod/groupsecret) for documentation.

# METHODS

## new

    $script = App::GroupSecret->new;

Construct a new script object.

## main

    $script->main(@ARGV);

Run a command with the given command-line arguments.

## filepath

    $filepath = $script->filepath;

Get the path to the keyfile.

## file

    $file = $script->file;

Get the [App::GroupSecret::File](https://metacpan.org/pod/App::GroupSecret::File) instance for the keyfile.

## private\_key

    $filepath = $script->private_key;

Get the path to a private key used to decrypt the keyfile.

# BUGS

Please report any bugs or feature requests on the bugtracker website
[https://github.com/chazmcgarvey/groupsecret/issues](https://github.com/chazmcgarvey/groupsecret/issues)

When submitting a bug or request, please include a test-file or a
patch to an existing test-file that illustrates the bug or desired
feature.

# AUTHOR

Charles McGarvey <chazmcgarvey@brokenzipper.com>

# COPYRIGHT AND LICENSE

This software is Copyright (c) 2017 by Charles McGarvey.

This is free software, licensed under:

    The MIT (X11) License
