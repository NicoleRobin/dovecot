/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ostream-private.h"

// 以buffer为输出的输出流
struct buffer_ostream {
	struct ostream_private ostream;
	buffer_t *buf;
	bool seeked;
};

static int o_stream_buffer_seek(struct ostream_private *stream, uoff_t offset)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;

	bstream->seeked = TRUE;
	stream->ostream.offset = offset;
	return 1;
}

static int
o_stream_buffer_write_at(struct ostream_private *stream,
			 const void *data, size_t size, uoff_t offset)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;

	buffer_write(bstream->buf, offset, data, size);
	return 0;
}

static ssize_t
o_stream_buffer_sendv(struct ostream_private *stream,
		      const struct const_iovec *iov, unsigned int iov_count)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;
	size_t left, n, offset;
	ssize_t ret = 0;
	unsigned int i;

	offset = bstream->seeked ? stream->ostream.offset : bstream->buf->used;

	for (i = 0; i < iov_count; i++) {
		left = bstream->ostream.max_buffer_size -
			stream->ostream.offset;
		n = I_MIN(left, iov[i].iov_len);
		buffer_write(bstream->buf, offset, iov[i].iov_base, n);
		stream->ostream.offset += n; offset += n;
		ret += n;
		if (n != iov[i].iov_len)
			break;
	}
	return ret;
}

static size_t
o_stream_buffer_get_used_size(const struct ostream_private *stream)
{
	struct buffer_ostream *bstream = (struct buffer_ostream *)stream;

	return bstream->buf->used;
}

struct ostream *o_stream_create_buffer(buffer_t *buf)
{
	struct buffer_ostream *bstream;
	struct ostream *output;

	// 这里有一个疑问，当该函数返回后，好像bstream指针丢失了（没有地方保存），
	// 那bstream指向的对象怎么释放呢？？？
	bstream = i_new(struct buffer_ostream, 1);
	/* we don't set buffer as blocking, because if max_buffer_size is
	   changed it can get truncated. this is used in various places in
	   unit tests. */
	bstream->ostream.max_buffer_size = (size_t)-1;
	bstream->ostream.seek = o_stream_buffer_seek;
	bstream->ostream.sendv = o_stream_buffer_sendv;
	bstream->ostream.write_at = o_stream_buffer_write_at;
	bstream->ostream.get_used_size = o_stream_buffer_get_used_size;

	bstream->buf = buf;
	output = o_stream_create(&bstream->ostream, NULL, -1);
	// output->real_stream指向bstream->ostream，在使用时将output->real_stream指针强制转换为bstream类型的指针
	// 因为ostream是bstream中的第一个成员，所以这个操作是可行的，这操作太。。。难理解了
	o_stream_set_name(output, "(buffer)");
	return output;
}
