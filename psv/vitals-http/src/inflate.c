#include "vh.h"

#include <string.h>
#include <zlib.h>

#define VH_INFLATE_INPUT 4096u

/* A gzip body's decompression, with zlib's memory in the pool */
struct VhInflater
{
    z_stream stream;
    int source_ended, finished;
    unsigned char input[VH_INFLATE_INPUT];
};

static voidpf zlib_alloc(voidpf opaque, uInt items, uInt size)
{
    (void)opaque;
    if (size != 0 && items > (uInt)-1 / size)
        return Z_NULL;
    return vh_alloc((size_t)items * size);
}

static void zlib_free(voidpf opaque, voidpf address)
{
    (void)opaque;
    vh_free(address);
}

VhInflater *vh_inflater_create(void)
{
    VhInflater *inflater = vh_alloc(sizeof(*inflater));
    if (inflater == NULL)
        return NULL;
    memset(inflater, 0, sizeof(*inflater));
    inflater->stream.zalloc = zlib_alloc;
    inflater->stream.zfree = zlib_free;
    /* gzip's header and trailer, not zlib's */
    if (inflateInit2(&inflater->stream, 16 + MAX_WBITS) != Z_OK) {
        vh_free(inflater);
        return NULL;
    }
    return inflater;
}

int vh_inflate(VhInflater *inflater, unsigned char *out, size_t out_size, VhInflateSource source, void *context)
{
    z_stream *stream = &inflater->stream;
    if (inflater->finished || out_size == 0)
        return 0;
    stream->next_out = out;
    stream->avail_out = (uInt)out_size;
    while (stream->avail_out == out_size && !inflater->finished) {
        if (stream->avail_in == 0 && !inflater->source_ended) {
            int count = source(context, inflater->input, sizeof(inflater->input));
            if (count < 0)
                return count;
            inflater->source_ended = count == 0;
            stream->next_in = inflater->input;
            stream->avail_in = (uInt)count;
        }
        int status = inflate(stream, Z_NO_FLUSH);
        if (status == Z_STREAM_END)
            inflater->finished = 1;
        else if (status == Z_MEM_ERROR)
            return (int)SCE_HTTP_ERROR_OUT_OF_MEMORY;
        else if (status != Z_OK && status != Z_BUF_ERROR)
            return (int)SCE_HTTP_ERROR_BAD_RESPONSE;
        /* The body ended before the stream did */
        else if (inflater->source_ended && stream->avail_in == 0 && stream->avail_out == out_size)
            return (int)SCE_HTTP_ERROR_BAD_RESPONSE;
    }
    return (int)(out_size - stream->avail_out);
}

void vh_inflater_destroy(VhInflater *inflater)
{
    inflateEnd(&inflater->stream);
    vh_free(inflater);
}
