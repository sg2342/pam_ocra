pam_ocra
=======

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

- 1.1:

  * fix timstamp_offset verification:
    broken termination condition in timstamp_offset verify loop did not
    account for timstamp_offset==0. The result was that verification would
    suceed for any timestamp.

  * fix counter_window and timstamp_offset verification:
    broken termination condition in counter_window verify loop did not
    account for counter_window==0. The result was that the verification
    would execute MAX_INT times before failing.

  * fix i368 builds:
    incorrect sign-compare and 64bit specific format string triggerd warnings
    which broke the build for i368 targets.

- 1.0: first release