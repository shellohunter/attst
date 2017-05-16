/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#ifndef __CACHE_H__
#define __CACHE_H__


#ifndef NULL_HANDLE
#define NULL_HANDLE ((unsigned int)0)
#endif

#ifndef handle
#define handle void *
//typedef void* handle;
#endif

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

handle cache_create(void);
void cache_destroy(handle hd);
void cache_clear(handle hd);
int cache_write(handle hd, const char * data, int len);
int cache_writes(handle hd, const char * str);
int cache_getdata(handle hd, char ** p);
//void cache_dump(handle hd);

#endif /* __CACHE_H__ */

