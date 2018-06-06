/* Copyright (c) 2010-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-mkstemp.h"
#include "fs-api.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "hash-format.h"
#include "str.h"
#include "message-parser.h"
#include "rfc822-parser.h"
#include "fs-api.h"
#include "istream-fs-file.h"
#include "istream-attachment-connector.h"
#include "istream-attachment-extractor.h"
#include "mail-user.h"
#include "index-mail.h"
#include "index-attachment.h"

enum mail_attachment_decode_option {
	MAIL_ATTACHMENT_DECODE_OPTION_NONE = '-',
	MAIL_ATTACHMENT_DECODE_OPTION_BASE64 = 'B',
	MAIL_ATTACHMENT_DECODE_OPTION_CRLF = 'C'
};

struct mail_save_attachment {
	pool_t pool;
	struct fs *fs;
	struct istream *input;

	struct fs_file *cur_file;
	ARRAY_TYPE(mail_attachment_extref) extrefs;
};

static const char *index_attachment_dir_get(struct mail_storage *storage)
{
	return mail_user_home_expand(storage->user,
				     storage->set->mail_attachment_dir);
}

// 判断hdr是否是附件
static bool index_attachment_want(const struct istream_attachment_header *hdr,
				  void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_attachment_part apart;

	i_zero(&apart);
	apart.part = hdr->part;
	apart.content_type = hdr->content_type;
	apart.content_disposition = hdr->content_disposition;

	if (ctx->part_is_attachment != NULL)
		return ctx->part_is_attachment(ctx, &apart);

	/* don't treat text/ parts as attachments */
	return hdr->content_type != NULL &&
		strncasecmp(hdr->content_type, "text/", 5) != 0;
}

// 打开临时文件
static int index_attachment_open_temp_fd(void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_storage *storage = ctx->transaction->box->storage;
	string_t *temp_path;
	int fd;

	// 为什么temp_path不需要调用str_free释放呢？？？
	temp_path = t_str_new(256);
	// 获取用户临时文件前缀
	mail_user_set_get_temp_prefix(temp_path, storage->user->set);

	fd = safe_mkstemp_hostpid(temp_path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		mail_storage_set_critical(storage,
			"safe_mkstemp(%s) failed: %m", str_c(temp_path));
		return -1;
	}
	// 为什么刚创建好fd，就unlink呢？
	if (unlink(str_c(temp_path)) < 0) {
		mail_storage_set_critical(storage,
			"unlink(%s) failed: %m", str_c(temp_path));
		i_close_fd(&fd);
		return -1;
	}
	return fd;
}

// 打开输出流
static int
index_attachment_open_ostream(struct istream_attachment_info *info,
			      struct ostream **output_r,
			      const char **error_r ATTR_UNUSED, void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_save_attachment *attach = ctx->data.attach;
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct mail_attachment_extref *extref;
	enum fs_open_flags flags = 0;
	const char *attachment_dir, *path, *digest = info->hash;
	guid_128_t guid_128;

	i_assert(attach->cur_file == NULL);

	if (storage->set->parsed_fsync_mode != FSYNC_MODE_NEVER)
		flags |= FS_OPEN_FLAG_FSYNC;

	if (strlen(digest) < 4) {
		/* make sure we can access first 4 bytes without accessing
		   out of bounds memory */
		digest = t_strconcat(digest, "\0\0\0\0", NULL);
	}

	guid_128_generate(guid_128);
	attachment_dir = index_attachment_dir_get(storage);
	// 构造附件路径
	path = t_strdup_printf("%s/%c%c/%c%c/%s-%s", attachment_dir,
			       digest[0], digest[1],
			       digest[2], digest[3], digest,
			       guid_128_to_string(guid_128));
	attach->cur_file = fs_file_init(attach->fs, path,
					FS_OPEN_MODE_REPLACE | flags);

	extref = array_append_space(&attach->extrefs);
	extref->start_offset = info->start_offset;
	extref->size = info->encoded_size;
	extref->path = p_strdup(attach->pool,
				path + strlen(attachment_dir) + 1);
	extref->base64_blocks_per_line = info->base64_blocks_per_line;
	extref->base64_have_crlf = info->base64_have_crlf;

	*output_r = fs_write_stream(attach->cur_file);
	return 0;
}

// 关闭输出流
static int
index_attachment_close_ostream(struct ostream *output, bool success,
			       const char **error, void *context)
{
	struct mail_save_context *ctx = context;
	struct mail_save_attachment *attach = ctx->data.attach;
	int ret = success ? 0 : -1;

	i_assert(attach->cur_file != NULL);

	if (ret < 0)
		fs_write_stream_abort_error(attach->cur_file, &output, "%s", *error);
	else if (fs_write_stream_finish(attach->cur_file, &output) < 0) {
		*error = t_strdup_printf("Couldn't create attachment %s: %s",
					 fs_file_path(attach->cur_file),
					 fs_file_last_error(attach->cur_file));
		ret = -1;
	}
	fs_file_deinit(&attach->cur_file);

	if (ret < 0) {
		array_delete(&attach->extrefs,
			     array_count(&attach->extrefs)-1, 1);
	}
	return ret;
}

// 开始存储附件
void index_attachment_save_begin(struct mail_save_context *ctx,
				 struct fs *fs, struct istream *input)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct mail_save_attachment *attach;
	struct istream_attachment_settings set;
	const char *error;
	pool_t pool;

	i_assert(ctx->data.attach == NULL);

	if (*storage->set->mail_attachment_dir == '\0')
		return;

	i_zero(&set);
	set.min_size = storage->set->mail_attachment_min_size;
	// 初始化hash格式，由conf.d/10-mail.conf:mail_attachment_hash选项指定，默认为sha1算法
	if (hash_format_init(storage->set->mail_attachment_hash,
			     &set.hash_format, &error) < 0) {
		/* we already checked this when verifying settings */
		i_panic("mail_attachment_hash=%s unexpectedly failed: %s",
			storage->set->mail_attachment_hash, error);
	}
	set.want_attachment = index_attachment_want; // 判断是否是附件
	set.open_temp_fd = index_attachment_open_temp_fd; // 打开临时文件
	set.open_attachment_ostream = index_attachment_open_ostream; // 打开附件输出流
	set.close_attachment_ostream = index_attachment_close_ostream; // 关闭附件输出流

	pool = pool_alloconly_create("save attachment", 1024);
	attach = p_new(pool, struct mail_save_attachment, 1);
	attach->pool = pool;
	attach->fs = fs;
	// 创建附件提取器
	attach->input = i_stream_create_attachment_extractor(input, &set, ctx);
	p_array_init(&attach->extrefs, attach->pool, 8);
	ctx->data.attach = attach;
}

// 检查是否有写入错误
static int save_check_write_error(struct mail_storage *storage,
				  struct ostream *output)
{
	if (output->last_failed_errno == 0)
		return 0;

	if (!mail_storage_set_error_from_errno(storage)) {
		mail_storage_set_critical(storage, "write(%s) failed: %s",
			o_stream_get_name(output), o_stream_get_error(output));
	}
	return -1;
}

// 继续存储附件
int index_attachment_save_continue(struct mail_save_context *ctx)
{
	struct mail_storage *storage = ctx->transaction->box->storage;
	struct mail_save_attachment *attach = ctx->data.attach;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	if (attach->input->stream_errno != 0)
		return -1;

	do {
		ret = i_stream_read(attach->input);
		if (ret > 0 || ret == -2) {
			// 获取的data为附件内容被提取后剩余的数据
			data = i_stream_get_data(attach->input, &size);
			o_stream_nsend(ctx->data.output, data, size);
			i_stream_skip(attach->input, size);
		}
		index_mail_cache_parse_continue(ctx->dest_mail);
		if (ret == 0 && !i_stream_attachment_extractor_can_retry(attach->input)) {
			/* need more input */
			return 0;
		}
	} while (ret != -1);

	if (attach->input->stream_errno != 0) {
		mail_storage_set_critical(storage, "read(%s) failed: %s",
					  i_stream_get_name(attach->input),
					  i_stream_get_error(attach->input));
		return -1;
	}
	if (ctx->data.output != NULL) {
		if (save_check_write_error(storage, ctx->data.output) < 0)
			return -1;
	}
	return 0;
}

// 结束存储附件
int index_attachment_save_finish(struct mail_save_context *ctx)
{
	struct mail_save_attachment *attach = ctx->data.attach;

	(void)i_stream_read(attach->input);
	i_assert(attach->input->eof);
	return attach->input->stream_errno == 0 ? 0 : -1;
}

// 释放附件数据
void index_attachment_save_free(struct mail_save_context *ctx)
{
	struct mail_save_attachment *attach = ctx->data.attach;

	if (attach != NULL) {
		i_stream_unref(&attach->input);
		pool_unref(&attach->pool);
		ctx->data.attach = NULL;
	}
}

// 获取附件的外部引用
const ARRAY_TYPE(mail_attachment_extref) *
index_attachment_save_get_extrefs(struct mail_save_context *ctx)
{
	return ctx->data.attach == NULL ? NULL :
		&ctx->data.attach->extrefs;
}

// 实际执行删除附件操作
static int
index_attachment_delete_real(struct mail_storage *storage,
			     struct fs *fs, const char *name)
{
	struct fs_file *file;
	const char *path;
	int ret;

	path = t_strdup_printf("%s/%s", index_attachment_dir_get(storage), name);
	file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
	if ((ret = fs_delete(file)) < 0)
		mail_storage_set_critical(storage, "%s", fs_last_error(fs));
	fs_file_deinit(&file);
	return ret;
}

// 删除附件
int index_attachment_delete(struct mail_storage *storage,
			    struct fs *fs, const char *name)
{
	int ret;

	T_BEGIN {
		ret = index_attachment_delete_real(storage, fs, name);
	} T_END;
	return ret;
}

// 将附件信息append到邮件中
void index_attachment_append_extrefs(string_t *str,
	const ARRAY_TYPE(mail_attachment_extref) *extrefs)
{
	const struct mail_attachment_extref *extref;
	bool add_space = FALSE;
	unsigned int startpos;

	array_foreach(extrefs, extref) {
		if (!add_space)
			add_space = TRUE;
		else
			str_append_c(str, ' ');
		str_printfa(str, "%"PRIuUOFF_T" %"PRIuUOFF_T" ",
			    extref->start_offset, extref->size);

		startpos = str_len(str);
		if (extref->base64_have_crlf)
			str_append_c(str, MAIL_ATTACHMENT_DECODE_OPTION_CRLF);
		if (extref->base64_blocks_per_line > 0) {
			str_printfa(str, "%c%u",
				    MAIL_ATTACHMENT_DECODE_OPTION_BASE64,
				    extref->base64_blocks_per_line * 4);
		}
		if (startpos == str_len(str)) {
			/* make it clear there are no options */
			str_append_c(str, MAIL_ATTACHMENT_DECODE_OPTION_NONE);
		}
		str_append_c(str, ' ');
		str_append(str, extref->path);
	}
}

// 解析附件解码选项
static bool
parse_extref_decode_options(const char *str,
			    struct mail_attachment_extref *extref)
{
	unsigned int num;

	if (*str == MAIL_ATTACHMENT_DECODE_OPTION_NONE)
		return str[1] == '\0';

	while (*str != '\0') {
		switch (*str) {
		case MAIL_ATTACHMENT_DECODE_OPTION_BASE64:
			str++; num = 0;
			while (*str >= '0' && *str <= '9') {
				num = num*10 + (*str-'0');
				str++;
			}
			if (num == 0 || num % 4 != 0)
				return FALSE;

			extref->base64_blocks_per_line = num/4;
			break;
		case MAIL_ATTACHMENT_DECODE_OPTION_CRLF:
			extref->base64_have_crlf = TRUE;
			str++;
			break;
		default:
			return FALSE;
		}
	}
	return TRUE;
}

// 解析附件
bool index_attachment_parse_extrefs(const char *line, pool_t pool,
				    ARRAY_TYPE(mail_attachment_extref) *extrefs)
{
	struct mail_attachment_extref extref;
	const char *const *args;
	unsigned int i, len;
	uoff_t last_voffset;

	args = t_strsplit(line, " ");
	len = str_array_length(args);
	if ((len % 4) != 0)
		return FALSE;

	last_voffset = 0;
	for (i = 0; args[i] != NULL; i += 4) {
		const char *start_offset_str = args[i+0];
		const char *size_str = args[i+1];
		const char *decode_options = args[i+2];
		const char *path = args[i+3];

		i_zero(&extref);
		if (str_to_uoff(start_offset_str, &extref.start_offset) < 0 ||
		    str_to_uoff(size_str, &extref.size) < 0 ||
		    extref.start_offset < last_voffset ||
		    !parse_extref_decode_options(decode_options, &extref))
			return FALSE;

		last_voffset += extref.size +
			(extref.start_offset - last_voffset);

		extref.path = p_strdup(pool, path);
		array_append(extrefs, &extref, 1);
	}
	return TRUE;
}

// 获取附件流，读取邮件的时候被调用
int index_attachment_stream_get(struct fs *fs, const char *attachment_dir,
				const char *path_suffix,
				struct istream **stream, uoff_t full_size,
				const char *ext_refs, const char **error_r)
{
	ARRAY_TYPE(mail_attachment_extref) extrefs_arr;
	const struct mail_attachment_extref *extref;
	struct istream_attachment_connector *conn;
	struct istream *input;
	struct fs_file *file;
	const char *path;
	int ret;

	*error_r = NULL;

	t_array_init(&extrefs_arr, 16);
	if (!index_attachment_parse_extrefs(ext_refs, pool_datastack_create(),
					    &extrefs_arr)) {
		*error_r = "Broken ext-refs string";
		return -1;
	}
	conn = istream_attachment_connector_begin(*stream, full_size);

	array_foreach(&extrefs_arr, extref) {
		path = t_strdup_printf("%s/%s%s", attachment_dir,
				       extref->path, path_suffix);
		file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY |
				    FS_OPEN_FLAG_SEEKABLE);
		input = i_stream_create_fs_file(&file, IO_BLOCK_SIZE);

		ret = istream_attachment_connector_add(conn, input,
					extref->start_offset, extref->size,
					extref->base64_blocks_per_line,
					extref->base64_have_crlf, error_r);
		i_stream_unref(&input);
		if (ret < 0) {
			istream_attachment_connector_abort(&conn);
			return -1;
		}
	}

	input = istream_attachment_connector_finish(&conn);
	i_stream_set_name(input, t_strdup_printf(
		"attachments-connector(%s)", i_stream_get_name(*stream)));
	i_stream_unref(stream);
	*stream = input;
	return 0;
}
