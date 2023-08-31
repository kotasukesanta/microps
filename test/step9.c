#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/loopback.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
}

static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    // シグナルハンドラを設定します。
    signal(SIGINT, on_signal);
    // プロトコルスタックを初期化します。
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    // ループバックデバイスを作成・登録します。
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    // プロトコルスタックを起動します。
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

static void
cleanup(void)
{
    net_shutdown();
}

int
main(int argc, char *argv[])
{
    ip_addr_t src, dst;
    size_t offset = IP_HDR_SIZE_MIN;

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src;
    // キーボードからの割り込みシグナルを受信するまで繰り返します。
    while (!terminate) {
        if (ip_output(IP_PROTOCOL_ICMP, test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
            errorf("ip_output() failure");
            break;
        }
        // 1秒スリープします。
        sleep(1);
    }
    // プロトコルスタックを停止します。
    cleanup();
    return 0;
}