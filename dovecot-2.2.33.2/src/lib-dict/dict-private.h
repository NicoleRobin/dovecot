#ifndef DICT_PRIVATE_H
#define DICT_PRIVATE_H

#include <time.h>
#include "dict.h"

struct dict_vfuncs {
	int (*init)(struct dict *dict_driver, const char *uri,
		    const struct dict_settings *set,
		    struct dict **dict_r, const char **error_r);
	void (*deinit)(struct dict *dict);
	int (*wait)(struct dict *dict);

	int (*lookup)(struct dict *dict, pool_t pool,
		      const char *key, const char **value_r);

	struct dict_iterate_context *
		(*iterate_init)(struct dict *dict, const char *const *paths,
				enum dict_iterate_flags flags);
	bool (*iterate)(struct dict_iterate_context *ctx,
			const char **key_r, const char **value_r);
	int (*iterate_deinit)(struct dict_iterate_context *ctx);

	struct dict_transaction_context *(*transaction_init)(struct dict *dict);
	int (*transaction_commit)(struct dict_transaction_context *ctx,
				  bool async,
				  dict_transaction_commit_callback_t *callback,
				  void *context);
	void (*transaction_rollback)(struct dict_transaction_context *ctx);

	void (*set)(struct dict_transaction_context *ctx,
		    const char *key, const char *value);
	void (*unset)(struct dict_transaction_context *ctx,
		      const char *key);
	void (*append)(struct dict_transaction_context *ctx,
		       const char *key, const char *value);
	void (*atomic_inc)(struct dict_transaction_context *ctx,
			   const char *key, long long diff);

	void (*lookup_async)(struct dict *dict, const char *key,
			     dict_lookup_callback_t *callback, void *context);
	bool (*switch_ioloop)(struct dict *dict);
	void (*set_timestamp)(struct dict_transaction_context *ctx,
			      const struct timespec *ts);
};

struct dict {
	const char *name;

	struct dict_vfuncs v;
	unsigned int iter_count;
	unsigned int transaction_count;
	struct dict_transaction_context *transactions;
};

struct dict_iterate_context {
	struct dict *dict;

	dict_iterate_callback_t *async_callback;
	void *async_context;

	unsigned int has_more:1;
	uint64_t row_count, max_rows;
};

struct dict_transaction_context {
	struct dict *dict;
	struct dict_transaction_context *prev, *next;

	struct timespec timestamp;

	unsigned int changed:1;
	unsigned int no_slowness_warning:1;
};

extern struct dict dict_driver_client;
extern struct dict dict_driver_file;
extern struct dict dict_driver_fs;
extern struct dict dict_driver_memcached;
extern struct dict dict_driver_memcached_ascii;
extern struct dict dict_driver_redis;
extern struct dict dict_driver_cdb;
extern struct dict dict_driver_fail;

extern struct dict_iterate_context dict_iter_unsupported;
extern struct dict_transaction_context dict_transaction_unsupported;

#endif
