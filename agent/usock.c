/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#include <openssl/md5.h>

#include "common.h"
#include "log.h"
#include "usock.h"



static int nextseq=0;

static int __send_ack(usock * sock, header * head,char * buf, int len, struct sockaddr * addr, socklen_t addrlen)
{
    LOG_TRACE("__send_ack");
    int i = 0;
    MD5_CTX ctx;
    unsigned char md[MD5_DIGEST_LENGTH];
    struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
    char ip[128];

    MD5_Init(&ctx);

    MD5_Update(&ctx, (void *)head, MSG_HEAD_LEN);
    MD5_Update(&ctx, (void *)buf, len);
    
    MD5_Final(md, &ctx);

    i = sendto(sock->rxsock, md, sizeof(md), 0, addr, addrlen);
    if (i != sizeof(md))
    {
        LOG_ERROR("failed to send ack, %d! %s", i, strerror(errno));
    }
    ASSERT(inet_ntop(AF_INET, &(addr_in->sin_addr), ip, sizeof(ip)));
    LOG_DEBUG("ack sent to %s:%d", ip, ntohs(addr_in->sin_port));
    hexdump("ack dump == ", md, MD5_DIGEST_LENGTH);
    return OK;
}

static int __wait_ack(usock * sock, unsigned char * chksum)
{
    int i = 0;
    char buf[MD5_DIGEST_LENGTH+1];

    ASSERT(sock);
    ASSERT(chksum);

    while (1)
    {
        hexdump("wait for ack", chksum, MD5_DIGEST_LENGTH);
        i = recv(sock->txsock, buf, sizeof(buf), 0);
        if (i <= 0)
        {
            LOG_ERROR("recv return %d, something is wrong.", i);
            continue;
        }
        if (0 == memcmp(buf, chksum, MD5_DIGEST_LENGTH))
            return OK;
        else
            return NG;
    }
}

static int __is_broadcast_addr(const struct in_addr * addr)
{
    ASSERT(addr);

    if (addr->s_addr == 0xFFFFFFFF)
        return TRUE;
    else
        return FALSE;
}

usock * usock_open()
{
    int i = 0;
    int enable = 1;
    usock * ss = NULL;


    ss = (usock *) malloc(sizeof(usock));
    ASSERT(ss);

    memset(ss, 0, sizeof(usock));

    ss->rxsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ss->rxsock < -1)
    {
        LOG_ERROR("failed to create ss->rxsock. %s", strerror(errno));
        goto __error_out;
    }

    struct sockaddr_in rxaddr;
    memset (&rxaddr, 0, sizeof(rxaddr));
    rxaddr.sin_family = AF_INET;
    rxaddr.sin_addr.s_addr = INADDR_ANY;
    rxaddr.sin_port = htons (AGENT_RXPORT);

    i = bind(ss->rxsock, (struct sockaddr *)&rxaddr, sizeof(rxaddr));
    if(i < -1)
    {
        LOG_ERROR("failed to bind ss->rxsock. %s", strerror(errno));
        goto __error_out;
    }

    i = setsockopt(ss->rxsock, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable));
    if (i < 0)
    {
        LOG_ERROR("IP_PKTINFO fail. %s", strerror(errno));
        goto __error_out;
    }

    ss->broadcast_addr.sin_family = AF_INET;
    ss->broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;
    ss->broadcast_addr.sin_port = htons (MASTER_RXPORT);

    ss->txsock = socket(AF_INET, SOCK_DGRAM, 0);
    if(ss->txsock < -1)
    {
        LOG_ERROR("failed to create ss->txsock. %s", strerror(errno));
        goto __error_out;
    }

    struct sockaddr_in txaddr;
    memset (&txaddr, 0, sizeof(txaddr));
    txaddr.sin_family = AF_INET;
    txaddr.sin_addr.s_addr = INADDR_ANY;
    txaddr.sin_port = htons (AGENT_TXPORT);

    i = bind(ss->txsock, (struct sockaddr *)&txaddr, sizeof(txaddr));
    if(i < -1)
    {
        LOG_ERROR("failed to bind ss->txsock. %s", strerror(errno));
        goto __error_out;
    }

    /* without this flag a socket cannot send broadcasting packet. */
    i = setsockopt(ss->txsock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));
    if (i < 0)
    {
        LOG_ERROR("SO_BROADCAST fail. %s", strerror(errno));
        goto __error_out;
    }

    return ss;

__error_out:
    if (ss)
    {
        if (ss->rxsock > 0) close(ss->rxsock);
        if (ss->txsock > 0) close(ss->txsock);
        free(ss);
    }

    return NULL;
}

int usock_send(usock * sock, const char *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int i = 0;
    int n = len;
    int m;
    const char * p = buf;
    MD5_CTX ctx;
    unsigned char md[MD5_DIGEST_LENGTH+1];
    const struct sockaddr_in * dest_addr_in = (struct sockaddr_in *)dest_addr;

    ASSERT(sock);

    do
    {
        m = MIN(n, CHUNK_SIZE);
        i = sendto(sock->txsock, p, m, flags, dest_addr, addrlen);
        if(i != m)
        {
            LOG_ERROR("%s, retry it.", strerror(errno));
            continue;
        }

        MD5_Init(&ctx);
        MD5_Update(&ctx, (void *)p, i);
        MD5_Final(md, &ctx);
        md[MD5_DIGEST_LENGTH] = 0;

        /* wait for ack */
        if (!__is_broadcast_addr(&(dest_addr_in->sin_addr)) && OK != __wait_ack(sock, md))
        {
            LOG_ERROR("no valid ack, retry!");
            continue;
        }

        n -= i;
        p += i;
    }
    while(n > 0);

    ASSERT(n == 0);
    return len - n;
}

int usock_broadcast(usock * sock, const char *buf, size_t len, int flags)
{
    ASSERT(sock);
    ASSERT(buf);

    if (len > CHUNK_SIZE)
    {
        LOG_ERROR("broadcasting msg length exceeds CHUNK_SIZE %d", CHUNK_SIZE);
        return NG;
    }

    return usock_send(sock, buf, len, flags,
        (struct sockaddr *)&(sock->broadcast_addr),
        sizeof(sock->broadcast_addr));
}

int usock_recv(usock * sock, char * buf, size_t len, int flags)
{ 
    ASSERT(sock);
    ASSERT(buf);
    if (len < CHUNK_SIZE)
    {
        LOG_ERROR("buf too small! need at least CHUNK_SIZE %d", CHUNK_SIZE);
        return NG;
    }

    int i = 0;
    int broadcasting = 0;

    struct sockaddr_in localaddr;
    char cmbuf[100];
    struct iovec iov[2];
    struct msghdr mh =
    {
        .msg_name = &localaddr,
        .msg_namelen = sizeof(localaddr),
        .msg_control = cmbuf,
        .msg_controllen = sizeof(cmbuf),
        .msg_iov = iov,
        .msg_iovlen = 2
    };
    header head;
    iov[0].iov_base =  &head;
    iov[0].iov_len = sizeof(header);
    iov[1].iov_base = buf;
    iov[1].iov_len = len;

    while (1)
    {
        i = recvmsg(sock->rxsock, &mh, 0 );
        if (i < 0)
        {
            LOG_ERROR("select recv fail. %s", strerror(errno));
            continue;
        }
        if (i > CHUNK_SIZE+MSG_HEAD_LEN)
        {
            LOG_ERROR("got something wrong? drop it.");
            continue;
        }
        hexdump("recvmsg got data", buf, i);

        LOG_DEBUG("total data bytes:%d",i);
        LOG_DEBUG("the seq is %d",head.seq);
        LOG_DEBUG("other in head %c%c%c%c %c%c%c%c",head.other[0],head.other[1],head.other[2],head.other[3],head.other[4],head.other[5],head.other[6],head.other[7]);
        buf[i-12]='\0';
        LOG_DEBUG("the message body is %s",buf);
    
        //LOG_DEBUG("the message body is %c",buf[0]);
        //check the seq in header
        if(head.seq!=nextseq){
            LOG_ERROR("old message, drop it.");
            __send_ack(sock, &head, buf, i, (struct sockaddr *)&localaddr, sizeof(localaddr));
            continue;
        }
        nextseq++;

        // to judge whether the message is broadcast
        struct cmsghdr *cmsg ;
        for (cmsg = CMSG_FIRSTHDR( &mh );
             cmsg != NULL;
             cmsg = CMSG_NXTHDR(&mh, cmsg))
        {
            // only take what we are interested.
            if (cmsg->cmsg_level != IPPROTO_IP ||
                cmsg->cmsg_type != IP_PKTINFO)
            {
                continue;
            }
            struct in_pktinfo * pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
            // struct in_pktinfo {
            //     unsigned int   ipi_ifindex;  /* Interface index */
            //     struct in_addr ipi_spec_dst;  Local address
            //     struct in_addr ipi_addr;     /* Header Destination
            //                                     address */
            // };
            struct in_addr * ipaddr = (struct in_addr *)&(pi->ipi_addr);
            #if 0
            /* save peer addr in order to send ack */
            src_addr.sin_family = AF_INET;
            src_addr.sin_addr.s_addr = pi->ipi_spec_dst.s_addr;//inet_addr("172.26.121.106");//
            src_addr.sin_port = htons(MASTER_TXPORT);

            LOG_DEBUG("pi->ipi_spec_dst.s_addr %08x", pi->ipi_spec_dst.s_addr);
            #endif
            char src_ip[128];
            //RecvAddr.sin_addr.S_un.S_un_b.s_b4 = (char)1
            if (!inet_ntop(AF_INET, &(localaddr.sin_addr), src_ip, sizeof(src_ip)))
            {
                LOG_ERROR("unable to get udp's src_ip!");
                break;
            }
            if ((ipaddr->s_addr & 0xFF) == 0xFF)
            {
                LOG_DEBUG("a broadcasting msg from %s", src_ip);
                broadcasting = TRUE;
            }
            else
            {
                LOG_DEBUG("a non-broadcasting msg from %s", src_ip);
            }
            break;
        }

        if (!broadcasting)
        {
            /* do not send ack for broadcasting msg */
            //sleep(1);
            __send_ack(sock, &head, buf, i-MSG_HEAD_LEN, (struct sockaddr *)&localaddr, sizeof(localaddr));
        }
        break;
    }


    return i-MSG_HEAD_LEN;
}


int usock_close(usock * sock)
{
    ASSERT(sock);
    close(sock->rxsock);
    close(sock->txsock);
    return OK;
}






