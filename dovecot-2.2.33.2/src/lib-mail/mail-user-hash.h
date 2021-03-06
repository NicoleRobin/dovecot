#ifndef MAIL_USER_HASH
#define MAIL_USER_HASH

/* Return a hash for username, based on given format. The format can use
   %n, %d and %u variables. The returned hash is never 0. */
unsigned int mail_user_hash(const char *username, const char *format);

#endif
