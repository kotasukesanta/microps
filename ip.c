#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "net.h"
#include "ip.h"

// プロトコルの受信キューからデータを受領します。
static void
ip_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    debugf("dev=%s, len=%zu", dev->name, len);
    debugdump(data, len);
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