/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#ifndef __USOCK_H__
#define __USOCK_H__

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


/* UDP supports various datagram length, but for better compatibility, we
 * always send data in 512 bytes chunks.
 */
#define CHUNK_SIZE (500)
#define MASTER_TXPORT (65071)
#define MASTER_RXPORT (65072)
#define AGENT_TXPORT (65171)
#define AGENT_RXPORT (65172)


typedef struct
{
    int rxsock;
    int txsock;
    struct sockaddr_in broadcast_addr;
} usock;


usock * usock_open();
int usock_send(usock * sock, const char *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);
int usock_broadcast(usock * sock, const char *buf, size_t len, int flags);
int usock_recv(usock * sock, char *buf, size_t len, int flags);
int usock_close(usock * sock);

#endif /* __USOCK_H__ */
