/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#include <openssl/md5.h>

#include "common.h"
#include "log.h"
#include "usock.h"


/* ack = {}
 *
 */
static int __send_ack(usock * sock, char * buf, int len, struct sockaddr * addr, socklen_t addrlen)
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

    sendto(sock->rxsock, md, sizeof(md), 0, addr, addrlen);
    LOG_VERBOSE("ack sent!");
    return OK;
}

static int __wait_ack(usock * sock, unsigned char * chksum)
{
	int i = 0;
	char buf[MD5_DIGEST_LENGTH+1];

	while (1)
	{
		LOG_DEBUG("wait for ack %s\n", chksum);
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
    ss->broadcast_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    ss->broadcast_addr.sin_port = htons (MASTER_RXPORT);

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

int usock_send(usock * sock, const void *buf, size_t len, int flags,
				const struct sockaddr *dest_addr, socklen_t addrlen)
{
    int i = 0;
    int n = len;
    int m;
    const char * p = buf;
    MD5_CTX ctx;
    unsigned char md[MD5_DIGEST_LENGTH+1];

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
        if (OK != __wait_ack(sock, md))
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


	return OK;
}


int usock_recv(usock * sock, void *buf, size_t len, int flags)
{
	int i = 0;
	struct sockaddr src_addr;
	socklen_t addrlen;
	ASSERT(sock);
	ASSERT(buf);

	if (len < CHUNK_SIZE)
	{
		LOG_ERROR("buffer too small! need at least CHUNK_SIZE %d", CHUNK_SIZE);
		return NG;
	}

	while (1)
	{
		i = recvfrom(sock->rxsock, buf, len, flags, (struct sockaddr *)&src_addr, &addrlen);

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

		__send_ack(sock, buf, i, &src_addr, addrlen);
		break;
	}


	return i;
}


int usock_close(usock * sock)
{
	ASSERT(sock);
	return OK;
}






