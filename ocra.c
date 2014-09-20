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

#include <sys/types.h>
#include <pwd.h>
#include <string.h>
#include <stdarg.h>
#include <db.h>
#include <fcntl.h>

#include <security/pam_constants.h>

#include <openssl/evp.h>
#include "rfc6287.h"

int
open_db(DB ** db, int flags, const char *path, const char *user_id)
{
	int r = PAM_SUCCESS;
	struct passwd *pwd = NULL;
	char *p1, *p2;

	if (NULL == (pwd = getpwnam(user_id)))
		return PAM_USER_UNKNOWN;

	asprintf(&p1, "%s/.ocra", pwd->pw_dir);
	if (NULL == (*db = dbopen(p1, flags, 0, DB_BTREE, NULL))) {
		if (NULL != path) {
			asprintf(&p2, "%s/%s", path, user_id);
			if (NULL == (*db = dbopen(p2, flags, 0, DB_BTREE, NULL)))
				r = PAM_NO_MODULE_DATA;
		} else {
			r = PAM_NO_MODULE_DATA;
		}
	}
	return r;
}

int
challenge(const char *path, const char *user_id, char **questions)
{
	int r;
	DB *db = NULL;
	DBT K, V;

	ocra_suite ocra;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (PAM_SUCCESS != (r = open_db(&db, O_EXLOCK | O_RDONLY, path, user_id)))
		return r;

	K.data = "suite";
	K.size = sizeof("suite");

	if (0 != (r = db->get(db, &K, &V, 0))) {
		db->close(db);
		return PAM_SERVICE_ERR;
	}
	r = rfc6287_parse_suite(&ocra, V.data);

	db->close(db);
	if (0 != r)
		return PAM_SERVICE_ERR;

	if (0 != rfc6287_challenge(&ocra, questions))
		return PAM_SERVICE_ERR;
	return PAM_SUCCESS;
}

int
verify(const char *path, const char *user_id, const char *questions,
    const char *response)
{
	int r;
	DB *db = NULL;
	DBT K, V;

	char *suite_string = NULL;
	uint8_t *key = NULL;
	size_t key_l = 0;
	uint64_t C = 0;
	uint8_t *P = NULL;
	size_t P_l = 0;
	uint64_t T = 0;
	int counter_window = 0;
	int timestamp_offset = 0;
	uint64_t next_counter;
	ocra_suite ocra;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));


	r = open_db(&db, O_EXLOCK | O_RDWR, path, user_id);
	if (PAM_SUCCESS != r)
		return r;


	K.data = "suite";
	K.size = sizeof("suite");
	if (0 != db->get(db, &K, &V, 0)) {
		r = PAM_SERVICE_ERR;
		goto out;
	}
	if (NULL == (suite_string = (char *)malloc(V.size))) {
		r = PAM_SERVICE_ERR;
		goto out;
	}
	memcpy(suite_string, V.data, V.size);

	if (0 != rfc6287_parse_suite(&ocra, suite_string)) {
		r = PAM_SERVICE_ERR;
		goto out;
	}
	K.data = "key";
	K.size = sizeof("key");
	if (0 != db->get(db, &K, &V, 0)) {
		r = PAM_SERVICE_ERR;
		goto out;
	}
	if (NULL == (key = (uint8_t *)malloc(V.size))) {
		r = PAM_SERVICE_ERR;
		goto out;
	}
	memcpy(key, V.data, V.size);
	key_l = V.size;

	if (ocra.flags & FL_C) {
		K.data = "C";
		K.size = sizeof("C");
		if (0 != db->get(db, &K, &V, 0)) {
			r = PAM_SERVICE_ERR;
			goto out;
		}
		C = ((uint64_t *)(V.data))[0];

		K.data = "counter_window";
		K.size = sizeof("counter_window");
		if (0 != db->get(db, &K, &V, 0)) {
			r = PAM_SERVICE_ERR;
			goto out;
		}
		counter_window = ((int *)(V.data))[0];
	}
	if (ocra.flags & FL_P) {
		K.data = "P";
		K.size = sizeof("P");
		if (0 != db->get(db, &K, &V, 0)) {
			r = PAM_SERVICE_ERR;
			goto out;
		}
		if (NULL == (P = (uint8_t *)malloc(V.size))) {
			r = PAM_SERVICE_ERR;
			goto out;
		}
		memcpy(P, V.data, V.size);
		P_l = V.size;
	}
	if (ocra.flags & FL_T) {
		K.data = "timestamp_offset";
		K.size = sizeof("timestamp_offset");
		if (0 != db->get(db, &K, &V, 0)) {
			r = PAM_SERVICE_ERR;
			goto out;
		}
		timestamp_offset = ((int *)(V.data))[0];

		if (0 != rfc6287_timestamp(&ocra, &T)) {
			r = PAM_SERVICE_ERR;
			goto out;
		}
	}
	r = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions, P, P_l,
	    NULL, 0, T, response, counter_window, &next_counter, timestamp_offset);
	if (r == 0) {
		r = PAM_SUCCESS;
		if (ocra.flags & FL_C) {
			K.data = "C";
			K.size = sizeof("C");
			V.data = (void *)&next_counter;
			V.size = sizeof(uint64_t);
			if (0 != db->put(db, &K, &V, 0)) {
				r = PAM_SERVICE_ERR;
				goto out;
			}
		}
	} else if (r == 1)
		r = PAM_AUTH_ERR;
	else
		r = PAM_SERVICE_ERR;

out:
	db->close(db);
	if (NULL != suite_string)
		free(suite_string);
	if (NULL != key)
		free(key);
	if (NULL != P)
		free(P);
	return r;
}
