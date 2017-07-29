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
#include <syslog.h>
#include <errno.h>

#include <security/pam_constants.h>

#include <openssl/evp.h>

#include "rfc6287.h"
#include "ocra.h"


#define KEY(k, s) memcpy(k.data = K_buf, s, k.size = sizeof(s));

static char K_buf[32];

static int
db_get(DB * db, DBT * K, DBT * V)
{
	int r;

	if (0 != (r = db->get(db, K, V, 0)))
		syslog(LOG_ERR, "db->get() failed for %s :%s",
		    (const char *)(K->data),
		    (1 == r) ? "key not in db" : (strerror(errno)));
	return r;
};

static int
open_db(DB ** db, int flags, const char *path, const char *user_id,
    const char *nodata, const char *fake_suite)
{
	int r = PAM_SUCCESS;
	struct passwd *pwd = NULL;
	char *p1, *p2;
	char *ep = NULL;

	if (NULL == (pwd = getpwnam(user_id)))
		return PAM_USER_UNKNOWN;

	asprintf(&p1, "%s/.ocra", pwd->pw_dir);
	if (NULL == (*db = dbopen(p1, flags, 0, DB_BTREE, NULL))) {
		if (NULL != path) {
			asprintf(&p2, "%s/%s", path, user_id);
			if (NULL == (*db = dbopen(p2, flags, 0, DB_BTREE, NULL))) {
				ep = p2;
			}
		} else {
			ep = p1;
		}
	}
	/* Handle file open errors */
	if (NULL != ep) {
		if (NULL != fake_suite) {
			/* Indicate that a fake challenge must be generated */
			r = PAM_NO_MODULE_DATA;
		} else if (NULL == nodata || strcmp(nodata, "fail") == 0) {
			/* We know we want to fail, so log an error. */
			syslog(LOG_ERR, "dbopen(\"%s\", ...) failed: %s", ep,
			    strerror(errno));
			r = PAM_AUTHINFO_UNAVAIL;
		} else {
			/* We will be changing the return code later */
			r = PAM_AUTHINFO_UNAVAIL;
		}
	}
	return r;
}


static int
fake_challenge(const char *suite_string, char **questions)
{
	int r;
	ocra_suite ocra;

	if (RFC6287_SUCCESS != (r = rfc6287_parse_suite(&ocra, suite_string))) {
		syslog(LOG_ERR, "rfc6287_parse_suite() failed for "
		    "fake_prompt \"%s\": %s", suite_string, rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	if (RFC6287_SUCCESS != (r = rfc6287_challenge(&ocra, questions))) {
		syslog(LOG_ERR, "rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	/* Indicate that a fake challenge was returned */
	return PAM_NO_MODULE_DATA;
}

int
challenge(const char *path, const char *user_id, char **questions,
    const char *nodata, const char *fake_suite)
{
	int r;
	DB *db = NULL;
	DBT K, V;

	ocra_suite ocra;

	memset(&K, 0, sizeof(K));
	memset(&V, 0, sizeof(V));

	if (PAM_SUCCESS !=
	    (r = open_db(&db, O_EXLOCK | O_RDONLY, path,
	    user_id, nodata, fake_suite))) {
		if (PAM_NO_MODULE_DATA == r)
			r = fake_challenge(fake_suite, questions);
		return r;
	}
	KEY(K, "suite");
	if (0 != db_get(db, &K, &V)) {
		db->close(db);
		return PAM_SERVICE_ERR;
	}
	r = rfc6287_parse_suite(&ocra, V.data);

	db->close(db);

	if (RFC6287_SUCCESS != r) {
		syslog(LOG_ERR, "rfc6287_parse_suite() failed: %s",
		    rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	if (RFC6287_SUCCESS != (r = rfc6287_challenge(&ocra, questions))) {
		syslog(LOG_ERR, "rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
		return PAM_SERVICE_ERR;
	}
	return PAM_SUCCESS;
}

int
verify(const char *path, const char *user_id, const char *questions,
    const char *response)
{
	int ret = PAM_SERVICE_ERR;
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

	/*
	 * This function should only be called if there was valid OCRA data for
	 * the user.  Fail out if it doesn't exist.
	 */
	r = open_db(&db, O_EXLOCK | O_RDWR, path, user_id, NULL, NULL);
	if (PAM_SUCCESS != r)
		return r;

	KEY(K, "suite");
	if (0 != db_get(db, &K, &V))
		goto out;
	if (NULL == (suite_string = (char *)malloc(V.size))) {
		syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
		goto out;
	}
	memcpy(suite_string, V.data, V.size);

	if (RFC6287_SUCCESS != (r = rfc6287_parse_suite(&ocra, suite_string))) {
		syslog(LOG_ERR, "rfc6287_parse_suite() failed: %s",
		    rfc6287_err(r));
		goto out;
	}
	KEY(K, "key");
	if (0 != db_get(db, &K, &V))
		goto out;
	if (NULL == (key = (uint8_t *)malloc(V.size))) {
		syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
		goto out;
	}
	memcpy(key, V.data, V.size);
	key_l = V.size;

	if (ocra.flags & FL_C) {
		KEY(K, "C");
		if (0 != db_get(db, &K, &V))
			goto out;
		memcpy(&C, V.data, sizeof(C));

		KEY(K, "counter_window");
		if (0 != db_get(db, &K, &V))
			goto out;
		memcpy(&counter_window, V.data, sizeof(counter_window));
	}
	if (ocra.flags & FL_P) {
		KEY(K, "P");
		if (0 != db_get(db, &K, &V))
			goto out;
		if (NULL == (P = (uint8_t *)malloc(V.size))) {
			syslog(LOG_ERR, "malloc() failed: %s", strerror(errno));
			goto out;
		}
		memcpy(P, V.data, V.size);
		P_l = V.size;
	}
	if (ocra.flags & FL_T) {
		KEY(K, "timestamp_offset");
		if (0 != db_get(db, &K, &V))
			goto out;
		memcpy(&timestamp_offset, V.data, sizeof(timestamp_offset));

		if (0 != rfc6287_timestamp(&ocra, &T)) {
			syslog(LOG_ERR, "rfc6287_timestamp() failed: %s",
			    rfc6287_err(r));
			goto out;
		}
	}
	r = rfc6287_verify(&ocra, suite_string, key, key_l, C, questions,
	    P, P_l, NULL, 0, T, response, counter_window, &next_counter,
	    timestamp_offset);
	if (RFC6287_SUCCESS == r) {
		if (ocra.flags & FL_C) {
			KEY(K, "C");
			V.data = &next_counter;
			V.size = sizeof(uint64_t);
			if (0 != db->put(db, &K, &V, 0)) {
				syslog(LOG_ERR, "db->put() failed for %s: %s",
				    (const char *)(K.data),
				    strerror(errno));
				goto out;
			}
		}
		ret = PAM_SUCCESS;
	} else if (RFC6287_VERIFY_FAILED == r)
		ret = PAM_AUTH_ERR;
	else
		syslog(LOG_ERR, "rfc6287_challenge() failed: %s",
		    rfc6287_err(r));
out:
	if (0 != db->close(db))
		syslog(LOG_ERR, "db->close() failed: %s", strerror(errno));
	free(suite_string);
	free(key);
	free(P);
	return ret;
}
