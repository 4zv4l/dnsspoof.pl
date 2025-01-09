# NAME

dnsspoof - simple dns spoofing Perl script

# SYNOPSIS

    ./dnsspoof.pl

# DESCRIPTION

_dnsspoof.pl_ is a simple perl script to do DNS spoofing, basically send a DNS response faster than the legitimate DNS server to redirect the target to another website.

You can easily change which interface to use with the _$dev_ variable and the domain name to redirect with their linked IP with the _$registered_ variable.

In the current script, only DNS request for _foo.bar_ will be spoofed with the IP of _example.com_ being _93.184.215.14_.
