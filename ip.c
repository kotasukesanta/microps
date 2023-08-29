#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "util.h"
#include "net.h"
#include "ip.h"

struct ip_hdr {
    uint8_t vhl;        // Version(4bit) + IHL(4bit)
    uint8_t tos;        // Type Of Service(8bit)
    uint16_t total;     // Total Length(16bit)
    uint16_t id;        // Identification(16bit)
    uint16_t offset;    // Flags(3bit) + Fragment Offset(13bit)
    uint8_t ttl;        // Time To Live(8bit)
    uint8_t protocol;   // Protocol(8bit)
    uint16_t sum;       // Header Checksum(16bit)
    ip_addr_t src;      // Source Address(32bit)
    ip_addr_t dst;      // Destination Address(32bit)
    uint8_t options[];  // Options(nbit) + Padding(n%32bit) フレキシブル配列メンバ
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

int
ip_addr_pton(const char *p, ip_addr_t *n)
{
    char *sp, *ep;
    int idx;
    long ret;

    sp = (char *)p;
    for (idx = 0; idx < 4; idx++) {
        ret = strtol(sp, &ep, 10);
        if (ret < 0 || ret > 255) {
            return -1;
        }
        if (ep == sp) {
            return -1;
        }
        if ((idx == 3 && *ep != '\0') || (idx != 3 && *ep != '.')) {
            return -1;
        }
        ((uint8_t *)n)[idx] = ret;
        sp = ep + 1;
    }
    return 0;
}

char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

static void
ip_dump(const uint8_t *data, size_t len)
{
}

// プロトコルの受信キューからデータを受領します。
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
}

// プロトコルを初期化します。
int
ip_init(void)
{
    if (net_protocol_register(NET_PROTOCOL_TYPE_IP, ip_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}