#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

// ネットワークデバイスのデバイス名長
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

// ネットワークデバイスの種別
#define NET_DEVICE_TYPE_DUMMY     0x0000
#define NET_DEVICE_TYPE_LOOPBACK  0x0001
#define NET_DEVICE_TYPE_ETHERNET  0x0002

// ネットワークデバイスの各種フラグ
#define NET_DEVICE_FLAG_UP        0x0001
#define NET_DEVICE_FLAG_LOOPBACK  0x0010
#define NET_DEVICE_FLAG_BROADCAST 0x0020
#define NET_DEVICE_FLAG_P2P       0x0040
#define NET_DEVICE_FLAG_NEED_ARP  0x0100

// ネットワークデバイスのアドレス長
#define NET_DEVICE_ADDR_LEN 16

// ネットワークデバイスのオープン（UP）チェック
#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
// ネットワークデバイスの状態（オープン・クローズ）取得
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")

/* NOTE: use same value as the Ethernet types */
#define NET_PROTOCOL_TYPE_IP   0x0800
#define NET_PROTOCOL_TYPE_ARP  0x0806
#define NTT_PROTOCOL_TYPE_IPV6 0x86dd

#define NET_IFACE_FAMILY_IP    1
#define NET_IFACE_FAMILY_IPV6  2

#define NET_IFACE(x) ((struct net_iface *)(x))

// ネットワークデバイス構造体
struct net_device {
    // 次のネットワークデバイスへのポインタ
    struct net_device *next;
    struct net_iface *ifaces; /* NOTE: if you want to add/delete the entries after net_run(), you need to protect ifaces with a mutex. */
    // ネットワークデバイスの番号（ユニーク）
    unsigned int index;
    // ネットワークデバイス名
    char name[IFNAMSIZ];
    // ネットワークデバイス種別
    uint16_t type;
    // MTU(Maximum Transmission Unit: 一度に送信可能な最大サイズ)
    uint16_t mtu;
    // 各種フラグ
    uint16_t flags;
    // ヘッダ長
    uint16_t hlen; /* header length */
    // アドレス長
    uint16_t alen; /* address length */
    // アドレス
    uint8_t addr[NET_DEVICE_ADDR_LEN];
    union {
        uint8_t peer[NET_DEVICE_ADDR_LEN];
        uint8_t broadcast[NET_DEVICE_ADDR_LEN];
    };
    // ネットワークデバイス操作
    struct net_device_ops *ops;
    // ネットワークデバイスが利用するプライベートデータへのポインタ
    void *priv;
};

// ネットワークデバイス操作構造体
struct net_device_ops {
    // ネットワークデバイスをオープン（UP）する関数ポインタ
    int (*open)(struct net_device *dev);
    // ネットワークデバイスをクローズ（DOWN）する関数ポインタ
    int (*close)(struct net_device *dev);
    // ネットワークデバイスを利用してデータを送信する関数ポインタ
    int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};

// インタフェース構造体
struct net_iface {
    struct net_iface *next;
    struct net_device *dev; /* back pointer to parent */
    int family;
    /* depends on implementation of protocols. */
};

// ネットワークデバイスのメモリを確保します。
extern struct net_device *
net_device_alloc(void);
// ネットワークデバイスをリストに登録します。
extern int
net_device_register(struct net_device *dev);
extern int
net_device_add_iface(struct net_device *dev, struct net_iface *iface);
extern struct net_iface *
net_device_get_iface(struct net_device *dev, int family);
// ネットワークデバイスを利用してデータを送信します。
extern int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

extern int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev));

extern int
net_timer_register(struct timeval interval, void (*handler)(void));
extern int
net_timer_handler(void);

// ネットワークデバイスからデータを受領します。
extern int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);
extern int
net_softirq_handler(void);

extern int
net_event_subscribe(void (*handler)(void *arg), void *arg);
extern int
net_event_handler(void);
extern void
net_raise_event(void);

// プロトコルスタックを起動します。
extern int
net_run(void);
// プロトコルスタックを停止します。
extern void
net_shutdown(void);
// プロトコルスタックを初期化します。
extern int
net_init(void);

#endif