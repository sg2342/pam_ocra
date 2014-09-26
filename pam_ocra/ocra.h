#ifndef _H_PAM_OCRA_H_
#define _H_PAM_OCRA_H_

int fake_challenge(const char *suite_string, char **questions);
int challenge(const char *path, const char *user_id, char **questions);
int verify(const char *path, const char *user_id, const char *questions, const char *response);

#endif
