/****************************************************************************
 * Copyright (c) 2017 Hua Shao <nossiac@163.com>
 ****************************************************************************/

#include "log.h"
#include "common.h"

void hexdump(char * txt, void * vbuf, size_t len)
{
    int i, c;
    char * buf = vbuf;
    char * base = buf;

    LOG_VERBOSE("======= hexdump =======>> %s, len %zu.\n", txt?txt:"", len);
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
    LOG_VERBOSE("======= hexdump =======<<\n");
}
