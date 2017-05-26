/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

/* log level */
enum
{
    LOG_LVL_NONE = 0,
    LOG_LVL_FATAL,
    LOG_LVL_ASSERT,
    LOG_LVL_ERROR,
    LOG_LVL_WARNING,
    LOG_LVL_DEBUG,
    LOG_LVL_TRACE,
    LOG_LVL_API,
    LOG_LVL_VERBOSE,
    LOG_LVL_ALL = 99,
};

#define LOG_TRACE(...) \
    if (__loglvl__ >= LOG_LVL_TRACE) do { \
        fprintf(stderr, "<trace> "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ". L%d, %s\n", __LINE__, __FUNCTION__); \
    } while(0)

#define LOG_DEBUG(...) \
    if (__loglvl__ >= LOG_LVL_DEBUG) do { \
        fprintf(stderr, "<dbg> "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ". L%d, %s\n", __LINE__, __FUNCTION__); \
    } while(0)

#define LOG_ERROR(...) \
    if (__loglvl__ >= LOG_LVL_ERROR) do { \
        fprintf(stderr, "<error> "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ". L%d, %s\n", __LINE__, __FUNCTION__); \
    } while(0)

#define LOG_VERBOSE(...) \
    if (__loglvl__ >= LOG_LVL_VERBOSE) do { \
        fprintf(stderr, __VA_ARGS__); \
    } while(0)

#define ASSERT(cond) \
    if (__loglvl__ > LOG_LVL_ASSERT) do { \
        if(!(cond)) \
        { \
            fprintf(stderr,"<assert> [%s] FAIL, %s L%d\n", #cond, __FUNCTION__, __LINE__); \
            exit(-1); \
        } \
    } while(0)


extern unsigned int __loglvl__;

#endif /* __LOG_H__ */

