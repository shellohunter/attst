/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <openssl/md5.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <linux/if.h>

#include "cache.h"

#define OK (0)
#define NG (-1)
#define AG (1)


#define MAX(a,b) (a)>(b)?(a):(b)
#define MIN(a,b) (a)>(b)?(b):(a)
/* UDP supports various datagram length, but for better compatibility, we
 * always send data in 512 bytes chunks.
 */
#define CHUNK_SIZE (500)
#define MASTER_TXPORT (65071)
#define MASTER_RXPORT (65072)
#define AGENT_TXPORT (65171)
#define AGENT_RXPORT (65172)

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



/* agent state */
enum
{
    INIT = 0, // initializing
    IDLE, // ready to take instructions
    ERROR, // some error occured.
    BUSY, // executing some instructions
};


typedef struct
{
    int state;
#if 1
    int rxsock;
    int txsock;
#else
    int sock;
#endif
    int ip;
    int master;
    struct sockaddr_in masteraddr;
    struct sockaddr_in broadcast_addr;
} Agent;


typedef struct __CGI__
{
    char * keyword;
    char * script;
    struct __CGI__ * next;
} CGI;


int    __loglvl__ = 0;
int    __daemon__ = 0;
char * __agent_ip__ = NULL;
char * __master_ip__ = NULL;
int __done__ = 0; // message loop ends
char * _cgi_root_ = ".";  // lua scripts path
pthread_mutex_t _cgi_mutex_ = PTHREAD_MUTEX_INITIALIZER;



void hexdump(char * txt, char * buf, size_t len)
{
    int i, c;
    char * base = buf;

    LOG_VERBOSE("=============>> %s, len %zu.\n", txt?txt:"", len);
    while ((int)len > 0)
    {
        LOG_VERBOSE("%08x: ", (int)(buf - base));
        for (i = 0;  i < 16;  i++)
        {
            if (i < len)
            {
                LOG_VERBOSE("%02X ", buf[i] & 0xFF);
            }
            else
            {
                LOG_VERBOSE("   ");
            }
            if (i == 7) LOG_VERBOSE(" ");
        }
        LOG_VERBOSE(" |");
        for (i = 0;  i < 16;  i++)
        {
            if (i < (int)len)
            {
                c = buf[i] & 0xFF;
                if ((c < 0x20) || (c >= 0x7F)) c = '.';
            }
            else
            {
                c = ' ';
            }
            LOG_VERBOSE("%c", c);
        }
        LOG_VERBOSE("|\n");
        len -= 16;
        buf += 16;
    }
    LOG_VERBOSE("=============<<\n");
}


CGI * __cgi__ = NULL;
int load_cgi(char * map)
{
    char line[1024];
    char * p = NULL;
    CGI * c = NULL;
    FILE * fp = fopen(map, "r");

    if (!fp)
    {
        LOG_ERROR("Failed to open cgi.map, %s.", strerror(errno));
        return NG;
    }

    while(fgets(line, sizeof(line), fp))
    {
        p = strchr(line, ' ');
        if (!p)
        {
            LOG_ERROR("illegal line! %s", line);
            continue;
        }

        *p = 0; // slit the line into 2 strings.
        c = malloc(sizeof(CGI));
        c->keyword = strdup(line);
        c->script = strdup(p+1);
        c->next = __cgi__;
        __cgi__ = c;
    }

    LOG_VERBOSE("dump cgi table:\n");
    c = __cgi__;
    while(c)
    {
        LOG_VERBOSE("\t%s ==> %s", c->keyword, c->script);
        c = c->next;
    }

    return OK;
}

int run_lua(char * luafile, handle cache, char * data, int len)
{
    int status, ret;
    lua_State * L = NULL;
    char luapath[128];

    ASSERT(luafile);
    ASSERT(luafile[0]);
    LOG_DEBUG("run lua %s, with data %p, len %d", luafile, data, len);

    if (_cgi_root_)
        snprintf(luapath, sizeof(luapath), "%s/%s", _cgi_root_, luafile);
    else
        snprintf(luapath, sizeof(luapath), "%s", luafile);

    L = luaL_newstate();
    luaL_openlibs(L);


    /* will push a code chunk onto the stack */
    status = luaL_loadfile(L, luapath);
    if (status)
    {
        LOG_ERROR("%s", lua_tostring(L, -1));
        goto __error;
    }

    if (data && len > 0)
    {
        lua_pushlstring(L, data, len);
        lua_setglobal(L, "data");
    }

    /* this will pop the code chunk, and push the return values, or error. */
    if (data && len > 0)
        ret = lua_pcall(L, 0, 1, 0);
    else
        ret = lua_pcall(L, 0, 1, 0);
    if (ret)
    {
        LOG_ERROR("%s", lua_tostring(L, -1));
        goto __error;
    }

    if (!lua_isstring(L, -1))
    {
        LOG_ERROR("invalid data type : %s!", lua_typename(L, lua_type(L, -1)));
        goto __error;
    }
    else
    {
        const char * rsp_buf = NULL;
        size_t rsp_len = 0;
        rsp_buf = lua_tolstring(L, -1, &rsp_len);
        hexdump("cgi return", (char *)rsp_buf, rsp_len);
        if (cache != NULL_HANDLE)
            cache_write(cache, rsp_buf, rsp_len);
    }

    lua_close(L);

    return OK;

__error:
    lua_close(L);

    return NG;
}


int send_chunk(int sock, char * data, int len, int flag, struct sockaddr * addr, socklen_t addrlen)
{
    int i = 0;
    int n = len;
    int m;

    do
    {
        m = MIN(n, CHUNK_SIZE);
        i = sendto(sock, data, m, flag, addr, addrlen);
        if(i != m)
        {
            LOG_ERROR("%s, retry it.", strerror(errno));
            continue;
        }

        n -= i;
    }
    while(n > 0);

    ASSERT(n == 0);
    return len - n;
}

/* An test agent will broadcast its identification periodically.
 */
void * hi(void * pvdata)
{
    Agent * agent = (Agent *)pvdata;
    static int counter = 0;
    handle cache = cache_create();
    int i = 0;
    char * data;
    int len = 0;

    LOG_DEBUG("hi thread start ... ");
    while(1)
    {

        if (agent->state == INIT)
            sleep(5);
        else
            sleep(10);

        i = run_lua("hi.lua", cache, NULL, 0); //__agent_ip__, strlen(__agent_ip__));
        if (i != OK)
        {
            LOG_ERROR("something is wrong!");
            cache_clear(cache);
            continue;
        }

        len = cache_getdata(cache, &data);

        hexdump("hi", data, len);
        LOG_DEBUG("hi \"%d\"", counter++);

        i = send_chunk(agent->txsock, data, len, 0,
                       (struct sockaddr *)&agent->broadcast_addr, sizeof(agent->broadcast_addr));
        cache_clear(cache);
        if(i != len)
        {
            LOG_ERROR("%s", strerror(errno));
        }
    }

    LOG_DEBUG("hi thread quit ... ");
    return NULL;
}



/* By default, lan ip of a test sets is always "192.168.1.1".
 * If more than one test sets are connected to the same switch,
 * there' will be a lot of IP conflicts. we have to randomize it.
 *
 * Not that it is not necessary for WAN PC agent, because it always
 * get a stable and unique IP address.
 */

int setip (int fd)
{
    struct ifreq ifr;
    struct sockaddr_in addr;
    int stat, s;

    memset(&ifr, 0, sizeof(ifr));
    memset(&addr, 0, sizeof(addr));
    strncpy(ifr.ifr_name, "br-lan", IFNAMSIZ);

    addr.sin_family = AF_INET;
    s = socket(addr.sin_family, SOCK_DGRAM, 0);
    stat = inet_pton(addr.sin_family, "192.168.1.1", &addr.sin_addr);
    if (stat == 0)
    {
        LOG_ERROR("inet_pton() - invalid ip");
        return NG;
    }

    if (stat == -1)
    {
        LOG_ERROR("inet_pton() - invalid family");
        return NG;
    }

    if (stat == 1);
    else
    {
        LOG_ERROR("inet_pton()");
        return NG;
    }

    ifr.ifr_addr = *(struct sockaddr *) &addr;
    /* This is just to test if address conversion happened properly */
    char buff[1024];
    const char * foo;
    foo = inet_ntop(AF_INET, &addr.sin_addr, buff, sizeof(buff));
    if (foo == NULL)
    {
        LOG_ERROR("inet_ntop()");
        return NG;
    }
    else
        printf("main = %s, addr = %s\n","192.168.1.1", buff);

    //if (ioctl(fd, SIOCSIFADDR, (caddr_t) &ifr) == -1)
    if (ioctl(s, SIOCSIFADDR, (caddr_t) &ifr) == -1)
    {
        LOG_ERROR("ioctl() - SIOCSIFADDR");
        return NG;
    }

    return OK;
}

int set_lan_ip(char * ip)
{
    int retry = 0;

    if (ip)
    {
        if (0 == strcasecmp(ip, "0.0.0.0"))
        {
            LOG_DEBUG("choose a random ip!");
        }
        else
        {
            LOG_DEBUG("choose ip %s!", ip);
        }
    }

    do
    {
        // random ip
        // check ip conflict
        // if yes, next loop.
        // if not, add ip to iinterface and return OK;
        srandom(time(NULL));
        random();

        retry++;
    }
    while (retry > 5);


    return NG;
}



/* Send a string (or binary data) to a specific address, using UDP.
 *
 */
int send_data(char * str, int len, struct sockaddr_in txaddr)
{

    return OK;
}

int validate(char * data, int len)
{
    int i = OK;
    handle cache = cache_create();
    i = run_lua("msg.lua", cache, data, len);
    if (i != OK)
    {
        LOG_ERROR("something is wrong!");
    }

    return i;
}



/* ack = {}
 *
 */
int send_ack(char * buf, int len, int sock, struct sockaddr * addr, socklen_t addrlen)
{
    MD5_CTX ctx;
    unsigned char md[MD5_DIGEST_LENGTH];
    int i;

    MD5_Init(&ctx);
    MD5_Update(&ctx, (void *)buf, len);
    MD5_Final(md, &ctx);

    LOG_VERBOSE("md5: ");
    for(i = 0; i< MD5_DIGEST_LENGTH; i++)
        LOG_VERBOSE("%02x", md[i]);
    LOG_VERBOSE("\n");

    sendto(sock, md, sizeof(md), 0, addr, addrlen);
    LOG_VERBOSE("ack sent!");
    return OK;
}


void usage(int argc,  char * const * argv)
{
    fprintf(stderr, "usage: %s [-i ip] [-I] [-d dbglvl] [-D] \n", argv[0]);
    fprintf(stderr, "    -i <ip>      set a ip for current device.");
    fprintf(stderr, "    -m <ip>      set ip of master.");
    fprintf(stderr, "    -l           choose a random ip.\n");
    fprintf(stderr, "    -d <dbglvl>  set debug level, 0 by default.\n");
    fprintf(stderr, "    -D           run as a daemon (baground mode).\n");
}

int handle_message(Agent * agent, char * msg, int len)
{
#define TMPFILE "/tmp/.autotest.tmp"
    int i = OK;
    handle cache = cache_create();

    LOG_TRACE("handle_message");

    /* leave the dirty work to lua */
    i = run_lua("msg.lua", cache, msg, len);
    if (i != OK)
    {
        LOG_ERROR("something is wrong!");
        return i;
    }


#if 0
    char buff[1024];
    FILE *resultFile;
    int fd = open(TMPFILE, O_WRONLY|O_APPEND|O_CREAT, S_IRUSR|S_IXUSR|S_IWUSR);
    if(fd < 0)
    {
        LOG_ERROR("Open file failed!");
        exit(NG);
    }
    write(fd, msg, len);
    close(fd);
    resultFile = popen("sh "TMPFILE,"r");
    if(resultFile==NULL)
    {
        LOG_ERROR("popen fail!");
        exit(NG);
    }
    while(fgets(buff, sizeof(buff), resultFile) != NULL)
    {
        hexdump("result", buff, strlen(buff));
        send(agent->sock, buff, strlen(buff), 0);
    }
    pclose(resultFile);
    if(unlink(TMPFILE)==-1)
    {
        LOG_ERROR("remove file error!");
        exit(1);
    }
#endif

    return OK;
}


int main(int argc, char ** argv)
{
    int i = 0;
    int enable = 1;
    fd_set rxfds;
    char rxbuf[2048];
    struct timeval timeout;
    pthread_t tid;
    Agent agent;
    handle cache;

    agent.state = INIT;
    //agent.master == INADDR_BROADCAST;
    cache = cache_create();

    while((i = getopt(argc, argv, "Dd:i:m:")) != -1)
    {
        switch (i)
        {
            case 'D':
                fprintf(stdout, "arg: run as a daemon.\n");
                __daemon__ = 1;
                break;
            case 'd':
                __loglvl__ = atoi(optarg);
                fprintf(stdout, "arg: dbg lvl %d.\n", __loglvl__);
                break;
            case 'm':
                __master_ip__= strdup(optarg);
                //agent.master == inet_addr(__master_ip__);
                fprintf(stdout, "arg: __master_ip__ %s.\n", __master_ip__);
                break;
            case 'i':
                __agent_ip__= strdup(optarg);
                //agent.ip == inet_addr(__agent_ip__);
                fprintf(stdout, "arg: __agent_ip__ %s.\n", __agent_ip__);
                break;
            case '?':
            default:
                usage(argc, argv);
                exit(NG);
        }
    }

    if (optind < argc)
    {
        usage(argc, argv);
        exit(NG);
    }


    LOG_TRACE("agent start");


    /* randomize lan ip */
    if (__agent_ip__)
    {
        set_lan_ip(__agent_ip__);
    }

    load_cgi("cgi.map");

    if (__master_ip__)
    {
        memset (&agent.masteraddr, 0, sizeof(agent.masteraddr));
        agent.masteraddr.sin_family = AF_INET;
        agent.masteraddr.sin_addr.s_addr = htonl(agent.master);
        agent.masteraddr.sin_port = htons (8508);
    }

    agent.rxsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(agent.rxsock < -1)
    {
        LOG_ERROR("failed to create agent.rxsock. %s", strerror(errno));
        exit(-1);
    }

    struct sockaddr_in rxaddr;
    memset (&rxaddr, 0, sizeof(rxaddr));
    rxaddr.sin_family = AF_INET;
    rxaddr.sin_addr.s_addr = INADDR_ANY;
    rxaddr.sin_port = htons (AGENT_RXPORT);

    i = bind(agent.rxsock, (struct sockaddr *)&rxaddr, sizeof(rxaddr));
    if(i < -1)
    {
        LOG_ERROR("failed to bind agent.rxsock. %s", strerror(errno));
        exit(-1);
    }

    i = setsockopt(agent.rxsock, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));
    if (i < 0)
    {
        LOG_ERROR("IP_PKTINFO fail. %s", strerror(errno));
        exit(-1);
    }

    agent.broadcast_addr.sin_family = AF_INET;
    agent.broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    agent.broadcast_addr.sin_port = htons (MASTER_RXPORT);

    //sendto(agent.rxsock, rxbuf, 32, 0, (struct sockaddr *)&agent.broadcast_addr, sizeof(agent.broadcast_addr));

    LOG_TRACE("agent.rxsock ready");

    agent.txsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(agent.txsock < -1)
    {
        LOG_ERROR("failed to create agent.txsock. %s", strerror(errno));
        exit(-1);
    }
    /* without this flag a socket cannot send broadcasting packet. */
    i = setsockopt(agent.txsock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));
    if (i < 0)
    {
        LOG_ERROR("SO_BROADCAST fail. %s", strerror(errno));
        exit(-1);
    }

    struct sockaddr_in txaddr;
    memset (&txaddr, 0, sizeof(txaddr));
    txaddr.sin_family = AF_INET;
    txaddr.sin_addr.s_addr = INADDR_ANY;
    txaddr.sin_port = htons (AGENT_TXPORT);

    i = bind(agent.txsock, (struct sockaddr *)&txaddr, sizeof(txaddr));
    if(i < -1)
    {
        LOG_ERROR("failed to bind agent.txsock. %s", strerror(errno));
        exit(-1);
    }

#if 0
    i = connect(agent.txsock, (struct sockaddr *) &txaddr, sizeof(txaddr));
    if(i < -1)
    {
        LOG_ERROR("failed to connect agent.txsock. %s", strerror(errno));
        exit(-1);
    }
#endif

    LOG_TRACE("agent.txsock ready");


    /* broadcast heartbeat all the time. */
    if (pthread_create(&tid, NULL, hi, (void*)&agent))
    {
        LOG_DEBUG("pthread create error %s.", strerror(errno));
    }

    char ipbuf[1024];
    while (1)
    {
        FD_ZERO(&rxfds);
        FD_SET(agent.rxsock, &rxfds);

        timeout.tv_sec = 60;
        timeout.tv_usec = 0;

        LOG_TRACE("waiting for data");
        i = select(agent.rxsock + 1, &rxfds, NULL, NULL, &timeout);
        if (i < 0)
        {
            if (EINTR == errno)
                continue;

            LOG_ERROR("select fail. %s", strerror(errno));
            exit(-1);
        }

        if (FD_ISSET(agent.rxsock, &rxfds))
        {
            #if 0
            struct sockaddr_in src_addr;
            socklen_t addrlen;
            i = recvfrom(agent.rxsock, rxbuf, sizeof(rxbuf), 0, (struct sockaddr *)&src_addr, &addrlen);
            LOG_DEBUG("got data from %s", inet_ntop(AF_INET, (struct sockaddr *)&src_addr.sin_addr, ipbuf, sizeof(ipbuf)));
            hexdump("rxbuf", rxbuf, i);
            #else
            char cmbuf[0x100];
            struct sockaddr_in src_addr, localaddr;
            socklen_t src_addrlen;
            char buffer[CHUNK_SIZE+1];
            struct iovec iov[1];
            iov[0].iov_base=buffer;
            iov[0].iov_len=sizeof ( buffer );
            struct msghdr mh =
            {
                .msg_name = &src_addr,
                .msg_namelen = sizeof (src_addr),
                .msg_control = cmbuf,
                .msg_controllen = sizeof (cmbuf ),
                .msg_iov=iov,                                                           
                .msg_iovlen=1
            };
            struct cmsghdr *cmsg = NULL;
            // if you want access to the data you need to init the msg_iovec fields


            memset(&src_addr, 0, sizeof(struct sockaddr_in));

            i = recvmsg(agent.rxsock, &mh, 0);

            #endif

            if (i < 0)
            {
                LOG_ERROR("select recv fail. %s", strerror(errno));
                continue;
            }

            if (i > CHUNK_SIZE)
            {
                LOG_ERROR("got something wrong? drop it.");
                continue;
            }

            /* if not broadcast, acknowledge it. */
            {
                for ( // iterate through all the control headers
                    cmsg = CMSG_FIRSTHDR(&mh);
                    cmsg != NULL;
                    cmsg = CMSG_NXTHDR(&mh, cmsg))
                {
                    // ignore the control headers that don't match what we want
                    if (cmsg->cmsg_level != IPPROTO_IP ||
                        cmsg->cmsg_type != IP_PKTINFO)
                    {
                        continue;
                    }
                    // struct in_pktinfo {
                    //     unsigned int   ipi_ifindex;  /* Interface index */
                    //     struct in_addr ipi_spec_dst;  Local address 
                    //     struct in_addr ipi_addr;     /* Header Destination
                    //                                     address */
                    // };
                    struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);

                    char dst[100],ipi[100];//用来保存转化后的源IP地址，目标主机地址
                    // pi->ipi_spec_dst 是UDP包中的路由目的IP地址（the destination in_addr）
                    // pi->ipi_addr 是UDP包中的头标识目的地址（the receiving interface in_addr）
                    if ((inet_ntop(AF_INET, &(pi->ipi_spec_dst), dst, sizeof(dst))) != NULL)
                    {
                        LOG_DEBUG ( "路由目的IP地址IP dst=%s",dst);
                    }
                    if ((inet_ntop(AF_INET, &(pi->ipi_addr), ipi, sizeof (ipi))) != NULL)
                    {
                        LOG_DEBUG ("头标识目的地址ipi_addr=%s",ipi);
                    }
                    if ((inet_ntop(AF_INET, &src_addr, ipi, sizeof (ipi))) != NULL)
                    {
                        LOG_DEBUG ("源地址=%s",ipi);
                    }


                }
            }
            send_ack(rxbuf, i, agent.rxsock, (struct sockaddr *)&src_addr, sizeof(struct sockaddr));


            /* save data into cache, in case there are more data comming. */
            cache_write(cache, rxbuf, i);


            /*
             * How do we know if a file has been fully sent?
             * A trick used here is to always send a chunk
             * less than CHUNK_SIZE as the last chunk (could be 0).
             */

            if (i != CHUNK_SIZE) /* the last chunk! */
            {
                char * data;
                int len = cache_getdata(cache, &data);
                hexdump("cache", data, len);


                /* check if it is a valid message */
                i = handle_message(&agent, data, len);
                if (i != OK)
                {
                    cache_clear(cache);
                    continue;
                }

                cache_clear(cache);
            }
        }
    }



    return 0;
}


