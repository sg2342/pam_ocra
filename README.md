pam_ocra
========

[RFC6287](http://tools.ietf.org/html/rfc6287) (OCRA) pam module

Limitations
-----------

  - intended target platform is FreeBSD
  - Session DataInput parameter is not supported

Installation
----------------

Use the FreeBSD port security/pam_ocra

Basic Use
--------------

    $ ocra_tool init -f ~foobar/.ocra \
              -s OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1 \
              -k 00112233445566778899aabbccddeeff00112233 \
              -c 10 -w 50 -p 1234

will create the ocra db file ".ocra" in the home directory of user "foobar";
set the OCRA suite, key, counter, counter_window and pin.

if for example /etc/pam.d/sshd has the line

    auth    sufficient    /usr/local/lib/pam_ocra.so

and sshd is configured to use PAM, "foobar" can log in using an OCRA token.

Changelog
---------

- 1.0: first release