#include <stdio.h>
#include <stddef.h>
#include <stdint.h>

#include "platform.h"

#include "util.h"
#include "net.h"

#define DUMMY_MTU UINT16_MAX /* maximum size of IP datagram */

#define DUMMY_IRQ INTR_IRQ_BASE

// ダミーデバイスのデータ送信関数
static int
dummy_transmit(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    /* drop data */
    // 割り込み処理スレッドにシグナルを送信します。
    intr_raise_irq(DUMMY_IRQ);
    return 0;
}

// ダミーデバイスの割り込みハンドラ
static int
dummy_isr(unsigned int irq, void *id)
{
    debugf("irq=%u, dev=%s", irq, ((struct net_device *)id)->name);
    return 0;
}

// ダミーデバイス操作構造体
static struct net_device_ops dummy_ops = {
    // ダミーデバイスを利用してデータを送信する関数ポインタ
    .transmit = dummy_transmit,
};

// ダミーデバイスを作成し、リストに登録します。
struct net_device *
dummy_init(void)
{
    struct net_device *dev;

    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_DUMMY;
    dev->mtu = DUMMY_MTU;
    dev->hlen = 0; /* non header */
    dev->alen = 0; /* non address */
    dev->ops = &dummy_ops;
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }
    // 割り込み要求をリストに登録します。
    intr_request_irq(DUMMY_IRQ, dummy_isr, INTR_IRQ_SHARED, dev->name, dev);
    debugf("initialized, dev=%s", dev->name);
    return dev;
}