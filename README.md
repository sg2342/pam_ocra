RFC6287 (OCRA) pam module

* Limitations:

  - code has not been reviewed
  - intended target platform is FreeBSD on amd64 only
  - Session DataInput parameter is not supported


* Basic Use

ocra_tool -f ~foobar/.ocra -s OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1 \
              -k 1122334455667788990011223344556677889900 -c 1 -w 42 -p 2342

will create the ocra db file ".ocra" in the home directory of user "foobar";
set the OCRA suite, key, counter, counter_window and pin.

if for example /etc/pam.d/sshd has the line

auth            sufficient      pam_ocra.so

and sshd is configured to use PAM, "foobar" can log in using an OCRA token.
