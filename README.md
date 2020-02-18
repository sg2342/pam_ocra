pam_ocra
=======
[![Build Status](https://travis-ci.org/sg2342/pam_ocra.svg?branch=master)](https://travis-ci.org/sg2342/pam_ocra)

[![Cirrus CI Build Status](https://api.cirrus-ci.com/github/sg2342/pam_ocra.svg)](https://cirrus-ci.com/github/sg2342/pam_ocra)

[RFC6287](http://tools.ietf.org/html/rfc6287) (OCRA) pam module

Limitations
-----------

  - intended target platforms are FreeBSD and Linux
  - Session DataInput parameter is not supported

Installation FreeBSD
----------------

Use the FreeBSD port security/pam_ocra

Build/Installation Linux
----------------

pam_ocra depends on libcrypto (from OpenSSL or LibreSSL), BerkleyDB 5.3
and Linux PAM


- debuild (Debian, Ubuntu, ...)

```
$ wget https://github.com/sg2342/pam_ocra/archive/1.5/pam_ocra-1.5.tar.gz
$ tar zxf pam_ocra-1.5.tag.gz
$ cd pam_ocra-1.5
$ debuild -i -us -uc -b
$ sudo dpkg -i ../libpam-ocra_1.5_$(dpkg --print-architecture)*.deb
```

- rpm (RHEL7, CentOS7, Fedora, ...)

```
$ wget https://github.com/sg2342/pam_ocra/archive/1.5/pam_ocra-1.5.tar.gz
$ rpmbuild -ta pam_ocra-1.5.tar.gz
$ sudo rpm -i ~/rpmbuild/RPMS/$(uname -m)/pam_ocra-1.5-1.*.$(uname -m).rpm
```

- other

```
$ wget https://github.com/sg2342/pam_ocra/archive/1.5/pam_ocra-1.5.tar.gz
$ tar zxf pam_ocra-1.5.tag.gz
$ cd pam_ocra-1.5
$ debuild -i -us -uc -b
$ make -C pam_ocra-1.5
$ sudo make -C pam_ocra-1.5 install
```

Basic Use
--------------

    $ man pam_ocra
    $ man ocra_tool
    $ ocra_tool init -f ~foobar/.ocra \
              -s OCRA-1:HOTP-SHA1-6:C-QN08-PSHA1 \
              -k 00112233445566778899aabbccddeeff00112233 \
              -c 0 -w 50 -p 1234

will create the ocra db file ".ocra" in the home directory of user "foobar";
set the OCRA suite, key, counter, counter_window and pin.

if for example /etc/pam.d/sshd has the line

    auth    required    pam_ocra.so

and sshd is configured to use PAM and ChallengeResponseAuthentication, "foobar"
can log in using an OCRA token.

Changelog
---------
- 1.5:

  * change credential file look-up:
    if the pam module option dir= is set ~/.ocra files will NOT be used

  * new formatting directive for cmsg/rmsg: %Nc (split challenge string
    to increase readability, default cmsg is now "OCRA Challenge: %4c";
    the challenge string is split into groups of 4 characters)

  * fix counter handling in ocra_tool sync

  * Linux support (Linux PAM, OpenSSL old and new API, rpm and deb packaging)

- 1.4:

  * add ocra_tool sync: synchronize counter with OTP device

  * introduce kill pin: If this pin is used, the the authentication fails, all
    future authentications also fail

  idea, interface, documentation and some code taken from

  https://github.com/nilsrasmuszen/pam_ocra

- 1.3:

  * fix pam_ocra "dir=" option

  * introduce pam_ocra "rmsg=", "cmsg=" and "nodata=" options

  contributed by Richard Nichols <rdn757@gmail.com>

- 1.2:

  * Constify two local variables to avoid -Wcast-qual warnings:
    https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=198113

- 1.1:

  * change ocra_tool(8) command line interface:
    - 'help' command removed
    - 'init' -P pinhash option added
    - 'init' -c option now also accepts hex counters
    - 'info' output format changed

  * fix ocra_tool counter input:
    the -c counter option did not work for the whole value range of the counter
    parameter.

  * fix gcc builds:
    which where broken due to (cast-qual, format, sign-compare, ...) warnings.

  * fix timstamp_offset verification:
    broken termination condition in timstamp_offset verify loop did not
    account for timstamp_offset==0. The result was that verification would
    succeed for any timestamp.

  * fix counter_window and timstamp_offset verification:
    broken termination condition in counter_window verify loop did not
    account for counter_window==0. The result was that the verification
    would execute MAX_INT times before failing.

  * fix i368 builds:
    incorrect sign-compare and 64bit specific format string triggered warnings
    which broke the build for i368 targets.

- 1.0: first release
