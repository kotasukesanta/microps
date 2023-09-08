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
#include "arp.h"

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

// プロトコル構造体（IPの上位プロトコルを管理）
struct ip_protocol {
    struct ip_protocol *next;
    uint8_t type;
    void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface);
};

// 経路情報構造体
struct ip_route {
    struct ip_route *next;
    ip_addr_t network;
    ip_addr_t netmask;
    ip_addr_t nexthop;
    struct ip_iface *iface;
};

const ip_addr_t IP_ADDR_ANY       = 0x00000000; /* 0.0.0.0 */
const ip_addr_t IP_ADDR_BROADCAST = 0xffffffff; /* 255.255.255.255 */

/* NOTE: if you want to add/delete the entries after net_run(), you need to protect these lists with a mutex. */
static struct ip_iface *ifaces;
static struct ip_protocol *protocols;
static struct ip_route *routes;

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

/* NOTE: must not be call after net_run() */
static struct ip_route *
ip_route_add(ip_addr_t network, ip_addr_t netmask, ip_addr_t nexthop, struct ip_iface *iface)
{
    struct ip_route *route;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    char addr3[IP_ADDR_STR_LEN];
    char addr4[IP_ADDR_STR_LEN];

    // Exercise 17-1: 経路情報の登録
    route = memory_alloc(sizeof(*route));
    if (!route) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    route->network = network;
    route->netmask = netmask;
    route->nexthop = nexthop;
    route->iface = iface;
    route->next = routes;
    routes = route;
    infof("route added: network=%s, netmask=%s, nexthop=%s, iface=%s dev=%s",
        ip_addr_ntop(route->network, addr1, sizeof(addr1)),
        ip_addr_ntop(route->netmask, addr2, sizeof(addr2)),
        ip_addr_ntop(route->nexthop, addr3, sizeof(addr3)),
        ip_addr_ntop(route->iface->unicast, addr4, sizeof(addr4)),
        NET_IFACE(iface)->dev->name
    );
    return route;
}

static struct ip_route *
ip_route_lookup(ip_addr_t dst)
{
    struct ip_route *route, *candidate = NULL;

    for (route = routes; route; route = route->next) {
        if ((dst & route->netmask) == route->network) {
            if (!candidate || ntoh32(candidate->netmask) < ntoh32(route->netmask)) {
                candidate = route;
            }
        }
    }
    return candidate;
}

/* NOTE: must not be call after net_run() */
int
ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway)
{
    ip_addr_t gw;

    if (ip_addr_pton(gateway, &gw) == -1) {
        errorf("ip_addr_pton() failure, addr=%s", gateway);
        return -1;
    }
    if (!ip_route_add(IP_ADDR_ANY, IP_ADDR_ANY, gw, iface)) {
        errorf("ip_route_add() failure");
        return -1;
    }
    return 0;
}

struct ip_iface *
ip_route_get_iface(ip_addr_t dst)
{
    struct ip_route *route;

    route = ip_route_lookup(dst);
    if (!route) {
        return NULL;
    }
    return route->iface;
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

    // Exercise 17-1: インタフェース登録時にそのネットワーク宛の経路情報を自動で登録する
    ip_route_add(iface->unicast & iface->netmask, iface->netmask, IP_ADDR_ANY, iface);

    // Exercise 7-4: IPインタフェースの登録
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

// プロトコルをリストに登録します。
int
ip_protocol_register(uint8_t type, void (*handler)(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface))
{
    struct ip_protocol *entry;

    // Exercise 9-1: 重複登録の確認
    for (entry = protocols; entry; entry = entry->next) {
        if (type == entry->type) {
            errorf("already registered, type=%u", type);
            return -1;
        }
    }
    // Exercise 9-2: プロトコルの登録
    // (1) 新しいプロトコルのエントリ用にメモリを確保
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    // (2) 新しいプロトコルのエントリに値を設定
    entry->next = protocols;
    entry->type = type;
    entry->handler = handler;
    // (3) プロトコルリスト（protocols）の先頭に挿入
    protocols = entry;
    infof("registered, type=%u", entry->type);
    return 0;    
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
    // Exercise 9-3: プロトコルの検索
    struct ip_protocol *ip_proto;
    for (ip_proto = protocols; ip_proto; ip_proto = ip_proto->next) {
        if (hdr->protocol == ip_proto->type) {
            ip_proto->handler(((uint8_t *)hdr) + hlen, total - hlen, hdr->src, hdr->dst, iface);
            return;
        }
    }
    /* unsupported protocol */
}

// IPデータグラムをデバイスから送信します。
static int
ip_output_device(struct ip_iface *iface, const uint8_t *data, size_t len, ip_addr_t dst)
{
    uint8_t hwaddr[NET_DEVICE_ADDR_LEN] = {};
    int ret;

    if (NET_IFACE(iface)->dev->flags & NET_DEVICE_FLAG_NEED_ARP) {
        if (dst == iface->broadcast || dst == IP_ADDR_BROADCAST) {
            memcpy(hwaddr, NET_IFACE(iface)->dev->broadcast, NET_IFACE(iface)->dev->alen);
        } else {
            // Exercise 14-5: arp_resolve() を呼び出してアドレスを解決する
            ret = arp_resolve(NET_IFACE(iface), dst, hwaddr);
            if (ret != ARP_RESOLVE_FOUND) {
                return ret;
            }
        }
    }
    // Exercise 8-4: デバイスから送信
    return net_device_output(NET_IFACE(iface)->dev, NET_PROTOCOL_TYPE_IP, data, len, hwaddr);
}

// IPデータグラムを作成し、デバイスから送信します。
static ssize_t
ip_output_core(struct ip_iface *iface, uint8_t protocol, const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, ip_addr_t nexthop, uint16_t id, uint16_t offset)
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
    memcpy(buf + hlen, data, len);
    debugf("dev=%s, dst=%s, protocol=%u, len=%u",
        NET_IFACE(iface)->dev->name, ip_addr_ntop(dst, addr, sizeof(addr)), protocol, total);
    ip_dump(buf, total);
    return ip_output_device(iface, buf, total, nexthop);
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
    struct ip_route *route;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    ip_addr_t nexthop;
    uint16_t id;

    if (src == IP_ADDR_ANY && dst == IP_ADDR_BROADCAST) {
        errorf("source address is required for broadcast addresses");
        return -1;
    }
    route = ip_route_lookup(dst);
    if (!route) {
        errorf("no route to host, addr=%s", ip_addr_ntop(dst, addr, sizeof(addr)));
        return -1;
    }
    iface = route->iface;
    if (src != IP_ADDR_ANY && src != iface->unicast) {
        errorf("unable to output with specified source address, addr=%s", ip_addr_ntop(src, addr, sizeof(addr)));
        return -1;
    }
    nexthop = (route->nexthop != IP_ADDR_ANY) ? route->nexthop : dst;
    if (NET_IFACE(iface)->dev->mtu < IP_HDR_SIZE_MIN + len) {
        errorf("too long, dev=%s, mtu=%u < %zu",
            NET_IFACE(iface)->dev->name, NET_IFACE(iface)->dev->mtu, IP_HDR_SIZE_MIN + len);
        return -1;
    }
    id = ip_generate_id();
    if (ip_output_core(iface, protocol, data, len, iface->unicast, dst, nexthop, id, 0) == -1) {
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