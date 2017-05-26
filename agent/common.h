/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

#define OK (0)
#define NG (-1)
#define AG (1)
#define TRUE (1)
#define FALSE (0)


#define MAX(a,b) (a)>(b)?(a):(b)
#define MIN(a,b) (a)>(b)?(b):(a)


void hexdump(char * txt, void * buf, size_t len);

#endif /* __COMMON_H__ */
