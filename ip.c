#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>

#include "platform.h"

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

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;

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

// IPインタフェースのメモリを確保します。
struct ip_iface *
ip_iface_alloc(const char *unicast, const char *netmask)
{
    struct ip_iface *iface;
    ip_addr_t u, n;

    iface = memory_alloc(sizeof(*iface));
    if (!iface) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    NET_IFACE(iface)->family = NET_IFACE_FAMILY_IP;
    // Exercise 7-3: IPインタフェースにアドレス情報を設定
    // (1) iface->unicast
    if (ip_addr_pton(unicast, &u) == -1) {
        errorf("ip_addr_pton(unicast) failure");
        memory_free(iface);
    }
    iface->unicast = u;
    // (2) iface->netmask
    if (ip_addr_pton(netmask, &n) == -1) {
        errorf("ip_addr_pton(netmask) failure");
        memory_free(iface);
    }
    iface->netmask = n;
    // (3) iface->broadcast
    iface->broadcast = (u & n) | ~n;
    return iface;
}

/* NOTE: must not be call after net_run() */
// IPインタフェースをネットワークデバイスとリストに登録します。
int
ip_iface_register(struct net_device *dev, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    // Exercise 7-4: IPインタフェースの登録
    // (1) デバイスにIPインタフェース（iface）を登録する
    if (net_device_add_iface(dev, NET_IFACE(iface)) == -1) {
        errorf("net_device_add_iface() failure");
        return -1;
    }
    // (2) IPインタフェースのリスト（ifaces）の先頭に iface を挿入する
    iface->next = ifaces;
    ifaces = iface;
    infof("registered: dev=%s, unicast=%s, netmask=%s, broadcast=%s", dev->name,
        ip_addr_ntop(iface->unicast, addr1, sizeof(addr1)),
        ip_addr_ntop(iface->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(iface->broadcast, addr3, sizeof(addr3)));
    return 0;
}

// IPアドレスを持つIPインタフェースをリストから取得します。
struct ip_iface *
ip_iface_select(ip_addr_t addr)
{
    // Exercise 7-5: IPインタフェースの検索
    struct ip_iface *entry;

    for (entry = ifaces; entry; entry = entry->next) {
        if (entry->unicast == addr) {
            return entry;
        }
    }
    return NULL;
}

// プロトコルの受信キューからデータを受領します。
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct ip_hdr *hdr;
    uint8_t v;
    uint16_t hlen, total, offset;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];

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
    if (0x0000 != cksum16((uint16_t *)data, hlen, 0)) {
        errorf("does not match checksum");
        return;
    }

    offset = ntoh16(hdr->offset);
    if (offset & 0x2000 || offset & 0x1fff) {
        errorf("fragments does not support");
        return;
    }
    // Exercise 7-6: IPデータグラムのフィルタリング
    // (1) デバイスに紐づくIPインタフェースを取得
    iface = (struct ip_iface *)net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (!iface) {
        errorf("fragments does not support");
        return;
    }
    // (2) 宛先IPアドレスの検証
    if (hdr->dst != iface->unicast) {
        if (hdr->dst != IP_ADDR_BROADCAST) {
            if (hdr->dst != iface->broadcast) {
                return;
            }
        }
    }
    debugf("dev=%s, iface=%s, protocol=%u, total=%u",
        dev->name, ip_addr_ntop(iface->unicast, addr, sizeof(addr)), hdr->protocol, total);
    ip_dump(data, total);
}

// IPデータグラムをデバイスから送信します。
static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            errorf("arp does not implement");
            return -1;
        }
    }
    // xercise 8-4: デバイスから送信
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, &dst);
}

// IPデータグラムを作成し、デバイスから送信します。
static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, uint16_t id, uint16_t offset)
{
    uint8_t buf[IP_TOTAL_SIZE_MAX];
    struct ip_hdr *hdr;
    uint16_t hlen, total;
    char addr[IP_ADDR_STR_LEN];

    hdr = (struct ip_hdr *)buf;
    // Exercise 8-3: IPデータグラムの生成
    // (1) IPヘッダの各フィールドに値を設定
    hlen = IP_HDR_SIZE_MIN;
    total = hlen + len;
    hdr->vhl = IP_VERSION_IPV4 << 4 | (hlen >> 2);
    hdr->tos = 0;
    hdr->total = hton16(total);
    hdr->id = hton16(id);
    hdr->offset = hton16(0x0000);
    hdr->ttl = 255;
    hdr->protocol = protocol;
    hdr->sum = hton16(0x0000);
    hdr->src = src;
    hdr->dst = dst;
    hdr->sum = cksum16((uint16_t *)hdr, hlen, 0);
    // (2) IPヘッダの直後にデータを配置（コピー）する
    memcpy(hdr + hlen, data, len);
    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
        NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, dst);
}

static uint16_t
ip_generate_id(void)
{
    static mutex_t mutex = MUTEX_INITIALIZER;
    static uint16_t id = 128;
    uint16_t ret;

    mutex_lock(&mutex);
    ret = id++;
    mutex_unlock(&mutex);
    return ret;
}

// IPの出力関数です。
ssize_t
ip_output(uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst)
{
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint16_t id;

    if (src == IP_ADDR_ANY) {
        errorf("ip routing does not implement");
        return -1;
    } else { /* NOTE: I'll rewrite this block later. */
        // Exercise 8-1: IPインタフェースの検索
        iface = ip_iface_select(src);
        if (!iface) {
            errorf("not found ip_iface src=%s", ip_addr_ntop(src, addr, sizeof(addr)));
            return -1;
        }
        // Exercise 8-2: 宛先へ到達可能か確認
        if ((dst & iface->netmask) != (iface->unicast & iface->netmask) && dst != IP_ADDR_BROADCAST) {
            errorf("unreachable dst=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
            return -1;
        }
    }
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u < %zu",
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, id, 0) == -1) {
        errorf("ip_output_core() failure");
        return -1;
    }
    return len;
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