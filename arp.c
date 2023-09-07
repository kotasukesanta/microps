#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
#define ARP_HRD_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY   2

#define ARP_CACHE_SIZE 32
#define ARP_CACHE_TIMEOUT 30 /* seconds */

#define ARP_CACHE_STATE_FREE       0
#define ARP_CACHE_STATE_INCOMPLETE 1
#define ARP_CACHE_STATE_RESOLVED   2
#define ARP_CACHE_STATE_STATIC     3

// ARPヘッダ構造体
struct arp_hdr {
    uint16_t hrd;  // ハードウェアアドレス種別
    uint16_t pro;  // プロトコルアドレス種別
    uint8_t hln;   // ハードウェアアドレス長
    uint8_t pln;   // プロトコルアドレス長
    uint16_t op;   // オペレーションコード
};

// ARPメッセージ構造体
struct arp_ether_ip {
    struct arp_hdr hdr;
    uint8_t sha[ETHER_ADDR_LEN];  // 送信元ハードウェアアドレス
    uint8_t spa[IP_ADDR_LEN];     // 送信元プロトコルアドレス
    uint8_t tha[ETHER_ADDR_LEN];  // ターゲットハードウェアアドレス
    uint8_t tpa[IP_ADDR_LEN];     // ターゲットプロトコルアドレス
};

// ARPキャッシュ構造体
struct arp_cache {
    unsigned char state;
    ip_addr_t pa;
    uint8_t ha[ETHER_ADDR_LEN];
    struct timeval timestamp;
};

static mutex_t mutex = MUTEX_INITIALIZER;
static struct arp_cache caches[ARP_CACHE_SIZE];  // ARPテーブル

static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/*
 * ARP Cache
 *
 * NOTE: ARP Cache functions must be called after mutex locked
 */

 static void
 arp_cache_delete(struct arp_cache *cache)
 {
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));
    // Exercise 14-1: キャッシュのエントリを削除する
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, sizeof(cache->ha));
    timerclear(&cache->timestamp);

 }

 static struct arp_cache *
 arp_cache_alloc(void)
 {
    struct arp_cache *entry, *oldest = NULL;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ARP_CACHE_STATE_FREE) {
            return entry;
        }
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = entry;
        }
    }
    arp_cache_delete(oldest);
    return oldest;
 }

 static struct arp_cache *
 arp_cache_select(ip_addr_t pa)
 {
    // Exercise 14-2: キャッシュの中からプロトコルアドレスが一致するエントリを探して返す
    struct arp_cache *entry;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ARP_CACHE_STATE_FREE) {
            continue;
        }
        if (entry->pa != pa) {
            continue;
        }
        return entry;
    }
    return NULL;
 }

 static struct arp_cache *
 arp_cache_update(ip_addr_t pa, const uint8_t *ha)
 {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // Exercise 14-3: キャッシュに登録されている情報を更新する
    // (1) arp_cache_select() でエントリを検索する
    cache = arp_cache_select(pa);
    if (!cache) {
        return NULL;
    }
    // (2) エントリの情報を更新する
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, sizeof(cache->ha));
    gettimeofday(&cache->timestamp, NULL);
    
    debugf("UPDATE: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));
    return cache;
 }

 static struct arp_cache *
 arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
 {
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    // Exercise 14-4: キャッシュに新しくエントリを登録する
    // (1) arp_cache_alloc() でエントリの登録スペースを確保する
    cache = arp_cache_alloc();
    if (!cache) {
        return NULL;
    }
    // (2) エントリの情報を設定する
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, sizeof(cache->ha));
    gettimeofday(&cache->timestamp, NULL);
    
    debugf("INSERT: pa=%s, ha=%s", ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));
    return cache;
 }

static int
arp_request(struct net_iface *iface, ip_addr_t tpa)
{
    struct arp_ether_ip request;

    // Exercise 15-2: ARP要求のメッセージを生成する
    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(request.sha, iface->dev->addr, sizeof(request.sha));
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, sizeof(request.spa));
    memcpy(request.tha, ETHER_ADDR_BROADCAST, sizeof(request.tha));
    memcpy(request.tpa, &tpa, sizeof(request.tpa));

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));
    // Exercise 15-3: デバイスの送信関数を呼び出してARP要求のメッセージを送信する
    return iface->dev->ops->transmit(iface->dev, NET_PROTOCOL_TYPE_ARP, (uint8_t *)&request, sizeof(request), iface->dev->broadcast);
}

static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;

    // Exercise 13-3: ARP応答メッセージの生成
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    memcpy(reply.sha, iface->dev->addr, sizeof(reply.sha));
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, sizeof(reply.spa));
    memcpy(reply.tha, tha, sizeof(reply.tha));
    memcpy(reply.tpa, &tpa, sizeof(reply.tpa));
    
    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;
    int marge = 0;

    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;
    // Exercise 13-1: 対応可能なアドレスペアのメッセージのみ受け入れる
    // (1) ハードウェアアドレスのチェック
    if (msg->hdr.hrd != ARP_HRD_ETHER && msg->hdr.hln != ETHER_ADDR_LEN) {
        return;
    }
    // (2) プロトコルアドレスのチェック
    if (msg->hdr.pro != ARP_PRO_IP && msg->hdr.pln != IP_ADDR_LEN) {
        return;
    }
    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    mutex_lock(&mutex);
    if (arp_cache_update(spa, msg->sha)) {
        /* updated */
        marge = 1;
    }
    mutex_unlock(&mutex);
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        if (!marge) {
            mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }
        // Exercise 13-2: ARP要求への応答
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

int
arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }
    mutex_lock(&mutex);
    cache = arp_cache_select(pa);
    if (!cache) {
        debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));

        // Exercise 15-1: ARPキャッシュに問い合わせ中のエントリを作成
        // (1) 新しいエントリのスペースを確保
        cache = arp_cache_alloc();
        if (!cache) {
            return ARP_RESOLVE_ERROR;
        }
        // (2) エントリの各フィールドに値を設定する
        cache->state = ARP_CACHE_STATE_INCOMPLETE;
        cache->pa = pa;
        gettimeofday(&cache->timestamp, NULL);
        mutex_unlock(&mutex);
        arp_request(iface, pa);
        return ARP_RESOLVE_INCOMPLETE;
    }
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
        mutex_unlock(&mutex);
        arp_request(iface, pa); /* just in case packet loss */
        return ARP_RESOLVE_INCOMPLETE;
    }
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    debugf("resolved, pa=%s, ha=%s",
        ip_addr_ntop(pa, addr1, sizeof(addr1)), ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

static void
arp_timer_handler(void)
{
}

int
arp_init(void)
{
    // Exercise 13-4: プロトコルスタックにARPを登録する
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}