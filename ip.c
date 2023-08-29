#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "util.h"
#include "net.h"
#include "ip.h"

// IPヘッダ構造体
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

// IPアドレス（文字列）をネットワークバイトオーダーのバイナリ値に変換
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

// IPアドレス（ネットワークバイトオーダーのバイナリ値）を文字列に変換
char *
ip_addr_ntop(ip_addr_t n, char *p, size_t size)
{
    uint8_t *u8;

    u8 = (uint8_t *)&n;
    snprintf(p, size, "%d.%d.%d.%d", u8[0], u8[1], u8[2], u8[3]);
    return p;
}

// IPデータグラムをダンプします。
static void
ip_dump(const uint8_t *data, size_t len)
{
    struct ip_hdr *hdr;
    uint8_t v, hl, hlen;
    uint16_t total, offset;
    char addr[IP_ADDR_STR_LEN];

    flockfile(stderr);
    hdr = (struct ip_hdr *)data;
    v = (hdr->vhl & 0xf0) >> 4;
    hl = hdr->vhl & 0x0f;
    hlen = hl << 2;
    fprintf(stderr, "        vhl: 0x%02x [v: %u, hl: %u (%u)]\n", hdr->vhl, v, hl, hlen);
    fprintf(stderr, "        tos: 0x%02x\n", hdr->tos);
    total = ntoh16(hdr->total);
    fprintf(stderr, "      total: %u (payload: %u)\n", total, total - hlen);
    fprintf(stderr, "         id: %u\n", ntoh16(hdr->id));
    offset = ntoh16(hdr->offset);
    fprintf(stderr, "     offset: 0x%04x [flags=%x, offset=%u]\n", offset, (offset & 0xe000) >> 13, offset & 0x1fff);
    fprintf(stderr, "        ttl: %u\n", hdr->ttl);
    fprintf(stderr, "   protocol: %u\n", hdr->protocol);
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "        src: %s\n", ip_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", ip_addr_ntop(hdr->dst, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

// プロトコルの受信キューからデータを受領します。
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    uint16_t sum;

    if (len < IP_HDR_SIZE_MIN) {
        errorf("too short");
        return;
    }
    hdr = (struct ip_hdr *)data;

    // Exercise 6-1: IPデータグラムの検証
    //  (1) バージョン
    v = (hdr->vhl & 0xf0) >> 4;
    if (IP_VERSION_IPV4 != v) {
        errorf("does not match IPv4");
        return;
    }
    //  (2) ヘッダ長
    hlen = (hdr->vhl & 0x0f) << 2;
    //  (3) トータル長
    total = ntoh16(hdr->total);
    //  (4) チェックサム
    sum = cksum16((uint16_t *)data, hlen, 0);
    if (0x0000 != sum) {
        errorf("does not match checksum");
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments does not support");
        return;
    }
    debugf("dev=%s, protocol=%u, total=%u", dev->name, hdr->protocol, total);
    ip_dump(data, total);
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