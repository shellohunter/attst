/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "cache.h"

/*
    Sometimes our code generates a lot of small pieces of data.
    to avoid invoking socket send frequently, we set up a buffer here.
    the data will not actually be sent onto a socket until:
        1) buffer is full. (we perform a auto-flush.)
        2) flush function is called.
*/

#ifndef ASSERT
#define ASSERT(cond) \
    do { \
        if(!(cond)) \
        { \
            fprintf(stderr,"<assert> [%s] FAIL, %s L%d\n", #cond, __FUNCTION__, __LINE__); \
            exit(-1); \
        } \
    } while(0)

#endif

typedef struct
{
    int     buflen;
    int     datalen;
    char *  buf;
} cache;


handle cache_create()
{
    cache * c;

    c = (cache *)malloc(sizeof(cache));
    if(!c) return 0;
    memset(c, 0, sizeof(cache));

    c->buf = malloc(1024);
    if(!c->buf) return 0;
    memset(c->buf, 0, 1024);

    c->buflen = 1024;
    c->datalen = 0;

    /*
    DBG("<%s> cache=%p, buf=%p, buflen=%d, datalen=%d.\n",
                   __FUNCTION__, cache, c->buf, c->buflen, c->datalen);
    */

    return (handle)c;
}

void cache_destroy(handle hd)
{
    cache * c = (cache *)hd;
    ASSERT(c);
    ASSERT(c->buf);
    /*
    DBG("<%s> cache=%p, buf=%p, buflen=%d, datalen=%d.\n",
                   __FUNCTION__, cache, cache->buf, cache->buflen, cache->datalen);
    */

    if (c->buf) free(c->buf);
    if (c) free(c);

}


void cache_clear(handle hd)
{
    cache * c = (cache *)hd;
    ASSERT(c);
    c->datalen = 0;
}


int cache_write(handle hd, const char * data, int len)
{
    cache * c = (cache *)hd;

    ASSERT(c);
    ASSERT(data);

    /* make sure c->datalen < c->buflen */

    while(len + c->datalen >= c->buflen)
    {
        c->buf = realloc(c->buf, c->buflen+1024);
        if(!c->buf) return 0;
        c->buflen += 1024;
    }

    memcpy(c->buf + c->datalen, data, len);
    c->datalen += len;

    return len;
}


int cache_writes(handle hd, const char * str)
{
    return cache_write(hd, str, strlen(str));
}


int cache_getdata(handle hd, char ** p)
{
    cache * c = (cache *)hd;

    ASSERT(c);
    *p = c->buf;

    /* Always keep a '\0' byte at the end of data field.
       It's not part of user data. This is for the safety
       of any string operation on c->buf.
    */

    ASSERT(c->datalen < c->buflen);
    c->buf[c->datalen] = 0;

    return c->datalen;
}

#if 0
void cache_dump(handle hd)
{
    cache * c = (cache *)hd;

    ASSERT(c);

    fprintf(stderr, "<%s> cache=%p, buf=%p, buflen=%d, datalen=%d.\n",
            __FUNCTION__, c, c->buf, c->buflen, c->datalen);
    dumphex("cache data:", c->buf, (c->datalen+0xF)&(~0xF));
}

#endif
