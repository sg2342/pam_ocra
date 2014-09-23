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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#include "ocra.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

static int
get_response(pam_handle_t *pamh, char *prompt, char **response)
{
	int ret;
	struct pam_message msg;
	const struct pam_message *msgp = &msg;
	struct pam_conv *conv = NULL;
	struct pam_response *presponse = NULL;

	pam_get_item(pamh, PAM_CONV, (const void **)&conv);
	pam_set_item(pamh, PAM_AUTHTOK, NULL);

	msg.msg_style = PAM_PROMPT_ECHO_ON;
	msg.msg = prompt;

	ret = (*conv->conv) (1, &msgp, &presponse, conv->appdata_ptr);

	if (NULL != presponse) {
		if (PAM_SUCCESS == ret) {
			*response = presponse->resp;
			presponse->resp = NULL;
		}
	}
	return ret;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
	int ret;
	const char *path = NULL;
	char *questions;
	char *user;
	char *response = NULL;
	char fmt[512];

	(void)flags;

	pam_get_item(pamh, PAM_USER, (const void **)&user);

	openlog("pam_ocra", 0, LOG_AUTHPRIV);
	if (argc)
		path = argv[0];
	if (PAM_SUCCESS != (ret = challenge(path, user, &questions))) {
		syslog(LOG_INFO, "ocra challenge() returned %d", ret);
		goto end;
	}
	snprintf(fmt, 512, "OCRA Challenge: %s\nOCRA  Response: ", questions);
	if (PAM_SUCCESS != (ret = get_response(pamh, fmt, &response))) {
		syslog(LOG_INFO, "get_response() failed: %d", ret);
		goto end;
	}
	if (PAM_SUCCESS != (ret = verify(path, user, questions, response)))
		syslog(LOG_INFO, "ocra verify() returned %d", ret);


	free(response);
end:
	closelog();
	return ret;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ocra");
#endif
