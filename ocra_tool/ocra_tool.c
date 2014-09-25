/*-
 * Copyright (c) 2014 Stefan Grundmann
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <sysexits.h>

#include <db.h>
#include <fcntl.h>

#include <openssl/evp.h>

#include "rfc6287.h"

#define KEY(k, s) k.data = (void*)s; k.size = sizeof(s);

static int
pin_hash(const ocra_suite * ocra, const char *pin, uint8_t **P, size_t *P_l)
{
	unsigned int s;
	EVP_MD_CTX ctx;

	*P = NULL;
	*P_l = mdlen(ocra->P_alg);
	EVP_MD_CTX_init(&ctx);
	if ((1 != EVP_DigestInit(&ctx, evp_md(ocra->P_alg))) ||
	    (1 != EVP_DigestUpdate(&ctx, pin, strlen(pin))) ||
	    (NULL == (*P = (uint8_t *)malloc(*P_l))) ||
	    (1 != EVP_DigestFinal(&ctx, *P, &s)) ||
	    (s != *P_l)) {
		free(*P);
		EVP_MD_CTX_cleanup(&ctx);
		return 0;
	}
	EVP_MD_CTX_cleanup(&ctx);
	return 0;
}

static int
key_from_hex(const ocra_suite * ocra, const char *key_string, uint8_t **key, size_t *key_l)
{
	uint32_t i;

	*key_l = mdlen(ocra->hotp_alg);

	if (strlen(key_string) != (*key_l * 2))
		return -1;
	if (NULL == (*key = (uint8_t *)malloc(*key_l)))
		return -1;
	for (i = 0; i < *key_l; i++)
		if (1 != sscanf(&key_string[i * 2], "%2hhx", *key + i)) {
			free(*key);
			return -1;
		}
	return 0;
}

static void
usage()
{
	const char *pn = getprogname();

	fprintf(stderr,
	    "usage: %s help\n"
	    "       %s info INFO_OPTIONS\n"
	    "       %s init INIT_OPTIONS\n",
	    pn, pn, pn);
	exit(1);
}

static void
cmd_help()
{
	const char *pn = getprogname();

	printf(
	    "%s: create db files used by pam_ocra\n"
	    "Help: %s help\n"
	    "Info: %s info -f <ocra_db_file>\n"
	    "Init: %s init -f <ocra_db_file> -s <suite_string> -k <key> ... \n"
	    " ... [-c <counter>] [-p <pin>] [-w <counter_window>] [-t <timestamp_offset>]\n\n",
	    pn, pn, pn, pn);
	printf(
	    " <ocra_db_file> - where the OCRA suite information of a user is stored\n"
	    "\tpam_ocra looks in $HOME/.ocra and $OCRA_DB_DIR/$USER\n"
	    " <suite_string> - the RFC6287 OCRA Suite\n"
	    " <key> - hex encoded key (size depends on CryptoFunction of in OCRA suite\n"
	    " <pin> - if the suite requires a pin/password parameter\n"
	    " <counter> - initial counter value (if required by suite)\n"
	    " <counter_window> - optional counter search window\n"
	    "\t(if suite has a counter parameter)\n"
	    " <timestamp_offset> - optional timestep offset (if suite has a \n"
	    "\ttimestamp parameter)\n");
}

static void
cmd_info(int argc, char **argv)
{
	int ch, ret;
	uint32_t i;
	char *fname = NULL;
	ocra_suite ocra;

	DB *db;
	DBT K, V;

	while (-1 != (ch = getopt(argc, argv, "f:"))) {
		switch (ch) {
		case 'f':
			fname = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if ((0 != argc) ||
	    (NULL == fname))
		usage();

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (NULL == (db = dbopen(fname, O_EXLOCK | O_RDONLY, 0600, DB_BTREE, NULL)))
		errx(EX_OSERR, "dbopen() failed: %s", strerror(errno));


	KEY(K, "suite");
	if (0 != (ret = db->get(db, &K, &V, 0)))
		errx(EX_OSERR, "db->get() failed: %s",
		    (ret == 1) ? "key not in db" : strerror(errno));
	printf("suite:\t\t%s\n", (char *)(V.data));

	if (0 != rfc6287_parse_suite(&ocra, V.data))
		errx(EX_SOFTWARE, "rfc6287_parse_suite() failed");

	KEY(K, "key");
	if (0 != (ret = db->get(db, &K, &V, 0)))
		errx(EX_OSERR, "db->get() failed: %s",
		    (ret == 1) ? "key not in db" : strerror(errno));
	if (mdlen(ocra.hotp_alg) != V.size)
		errx(EX_SOFTWARE, "key size does not match suite!");

	printf("key:\t\t");
	for (i = 0; i < V.size; i++)
		printf("%0.02x", ((uint8_t *)(V.data))[i]);
	printf("\n");

	if (ocra.flags & FL_C) {
		KEY(K, "C");
		if (0 != (ret = db->get(db, &K, &V, 0)))
			errx(EX_OSERR, "db->get() failed: %s",
			    (ret == 1) ? "key not in db" : strerror(errno));
		printf("counter:\t%d\n", ((int *)(V.data))[0]);

		KEY(K, "counter_window");
		if (0 != (ret = db->get(db, &K, &V, 0)))
			errx(EX_OSERR, "db->get() failed: %s",
			    (ret == 1) ? "key not in db" : strerror(errno));
		printf("counter_window: %d\n", ((int *)(V.data))[0]);
	}
	if (ocra.flags & FL_P) {
		KEY(K, "P");
		if (0 != (ret = db->get(db, &K, &V, 0)))
			errx(EX_OSERR, "db->get() failed: %s",
			    (ret == 1) ? "key not in db" : strerror(errno));

		if (mdlen(ocra.P_alg) != V.size)
			errx(EX_SOFTWARE, "pin hash size does not match suite!");
		printf("pin_hash:\t");
		for (i = 0; i < V.size; i++)
			printf("%0.02x", ((uint8_t *)(V.data))[i]);
		printf("\n");
	}
	if (ocra.flags & FL_T) {
		KEY(K, "timestamp_offset");
		if (0 != (ret = db->get(db, &K, &V, 0)))
			errx(EX_OSERR, "db->get() failed: %s",
			    (ret == 1) ? "key not in db" : strerror(errno));
		printf("timestamp_offset: %d\n", ((int *)(V.data))[0]);
	}
	if (0 != (db->close(db)))
		errx(EX_OSERR, "db->close() failed: %s", strerror(errno));
}

static void
test_input(const ocra_suite * ocra, const char *suite_string,
    const uint8_t *key, size_t key_l, uint64_t C, const uint8_t *P,
    size_t P_l, int counter_window, int timestamp_offset)
{
	uint64_t T;
	uint64_t next_counter;
	char *questions;
	char *response;

	if (0 != rfc6287_challenge(ocra, &questions))
		errx(EX_SOFTWARE, "rfc6287_challenge() failed");

	if (0 != rfc6287_timestamp(ocra, &T))
		errx(EX_SOFTWARE, "rfc6287_timestamp() failed");

	if (0 != rfc6287_ocra(ocra, suite_string, key, key_l, C, questions,
	    P, P_l, NULL, 0, T, &response))
		errx(EX_SOFTWARE, "rfc6287_ocra() failed");

	if (0 != rfc6287_verify(ocra, suite_string, key, key_l, C, questions, P,
	    P_l, NULL, 0, T, response, counter_window, &next_counter, timestamp_offset))
		errx(EX_SOFTWARE, "rfc6287_verify() failed");

	free(response);
	free(questions);
}

static void
write_db(const char *fname, const char *suite_string,
    const uint8_t *key, size_t key_l, uint64_t C, const uint8_t *P,
    size_t P_l, int counter_window, int timestamp_offset)
{
	DB *db;
	DBT K, V;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (NULL == (db = dbopen(fname, O_CREAT | O_EXLOCK | O_RDWR | O_TRUNC,
	    0600, DB_BTREE, NULL)))
		errx(EX_OSERR, "dbopen() failed: %s", strerror(errno));

	KEY(K, "suite");
	V.data = (void *)suite_string;
	V.size = strlen(suite_string) + 1;
	if (0 != (db->put(db, &K, &V, R_NOOVERWRITE)))
		errx(EX_OSERR, "db->put() failed: %s", strerror(errno));

	KEY(K, "key");
	V.data = (void *)key;
	V.size = key_l;
	if (0 != (db->put(db, &K, &V, R_NOOVERWRITE)))
		errx(EX_OSERR, "db->put() failed: %s", strerror(errno));

	KEY(K, "C");
	V.data = &C;
	V.size = sizeof(C);
	if (0 != (db->put(db, &K, &V, R_NOOVERWRITE)))
		errx(EX_OSERR, "db->put() failed: %s", strerror(errno));

	KEY(K, "V");
	V.data = (void *)P;
	V.size = P_l;
	if (0 != (db->put(db, &K, &V, R_NOOVERWRITE)))
		errx(EX_OSERR, "db->put() failed: %s", strerror(errno));

	KEY(K, "counter_window");
	V.data = &counter_window;
	V.size = sizeof(counter_window);
	if (0 != (db->put(db, &K, &V, R_NOOVERWRITE)))
		errx(EX_OSERR, "db->put() failed: %s", strerror(errno));

	KEY(K, "timestamp_offset");
	V.data = &timestamp_offset;
	V.size = sizeof(timestamp_offset);
	if (0 != (db->put(db, &K, &V, R_NOOVERWRITE)))
		errx(EX_OSERR, "db->put() failed: %s", strerror(errno));

	if (0 != (db->sync(db, 0)))
		errx(EX_OSERR, "db->sync() failed: %s", strerror(errno));

	if (0 != (db->close(db)))
		errx(EX_OSERR, "db->close() failed: %s", strerror(errno));


}

static void
cmd_init(int argc, char **argv)
{
	int ch;
	char *fname = NULL;
	char *suite_string = NULL;
	char *key_string = NULL;
	char *pin_string = NULL;
	char *counter_string = NULL;
	char *counter_window_string = NULL;
	char *timestamp_offset_string = NULL;

	ocra_suite ocra;
	uint64_t C = 0;
	int timestamp_offset = 0;
	int counter_window = 0;

	uint8_t *P = NULL;
	size_t P_l = 0;
	uint8_t *key = NULL;
	size_t key_l = 0;

	while (-1 != (ch = getopt(argc, argv, "f:s:k:p:c:w:t:"))) {
		switch (ch) {
		case 'f':
			fname = optarg;
			break;
		case 's':
			suite_string = optarg;
			break;
		case 'k':
			key_string = optarg;
			break;
		case 'c':
			counter_string = optarg;
			break;
		case 'p':
			pin_string = optarg;
			break;
		case 'w':
			counter_window_string = optarg;
			break;
		case 't':
			timestamp_offset_string = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	if ((0 != argc) ||
	    (NULL == fname) ||
	    (NULL == suite_string) ||
	    (NULL == key_string))
		usage();

	if (0 != rfc6287_parse_suite(&ocra, suite_string))
		errx(EX_CONFIG, "invalid suite_string");
	if (ocra.flags & FL_C) {
		if (NULL == counter_string)
			errx(EX_CONFIG, "suite requires counter parameter "
			    "(-c <counter> missing)");
		if (-1 == (C = parse_num(counter_string)))
			errx(EX_CONFIG, "invalid counter value");
		if (NULL != counter_window_string)
			if (-1 == (counter_window = parse_num(counter_window_string)))
				errx(EX_CONFIG, "invalud counter window value");
	} else {
		if (NULL != counter_string)
			errx(EX_CONFIG, "suite does not require counter parameter "
			    "(-c <counter> must not be set)");
		if (NULL != counter_window_string)
			errx(EX_CONFIG, "suite does not require counter parameter "
			    " (-w <counter_window> must not be set)");
	}
	if (ocra.flags & FL_S)
		errx(EX_CONFIG, "suite requires session parameter (S) which"
		    " is not supported by pam_ocra");
	if (ocra.flags & FL_T) {
		if (-1 == (timestamp_offset = parse_num(timestamp_offset_string)))
			errx(EX_CONFIG, "invalid timestamp offset value");
	} else if (NULL != timestamp_offset_string)
		errx(EX_CONFIG, "suite does nor require timestamp parameter "
		    " (-t <timestamp_offset> must not be set)");
	if (0 == ocra.hotp_trunc)
		errx(EX_CONFIG, "suite specifies no (0) truncation in CryptoFunction."
		    " This is not supported by pam_ocra");
	if (ocra.flags & FL_P) {
		if (NULL == pin_string)
			errx(EX_CONFIG, "suite requires pin parameter (-p <pin> missing)");
		if (0 != pin_hash(&ocra, pin_string, &P, &P_l))
			errx(EX_SOFTWARE, "internal error, pin_hash() failed");
	} else if (NULL != pin_string)
		errx(EX_CONFIG, "suite does not require pin parameter"
		    " (-p <pin> must not be set)");
	if (0 != key_from_hex(&ocra, key_string, &key, &key_l))
		errx(EX_CONFIG, "invalid key");

	test_input(&ocra, suite_string, key, key_l, C, P, P_l,
	    counter_window, timestamp_offset);

	write_db(fname, suite_string, key, key_l, C, P, P_l,
	    counter_window, timestamp_offset);

}

int
main(int argc, char **argv)
{
	if (argc < 2)
		usage();
	if (0 == strcmp(argv[1], "init"))
		cmd_init(argc - 1, argv + 1);
	else if (0 == strcmp(argv[1], "info"))
		cmd_info(argc - 1, argv + 1);
	else if (0 == strcmp(argv[1], "help"))
		cmd_help();
	else
		usage();
	return 0;
}
