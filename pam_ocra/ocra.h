#ifndef _H_PAM_OCRA_H_
#define _H_PAM_OCRA_H_

int challenge(
	const char *path,
	const char *user_id,
	char **questions,
	const char *nodata,
	const char *fake_suite);

int verify(
	const char *path,
	const char *user_id,
	const char *questions,
	const char *response);

#endif
