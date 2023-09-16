#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    close(0); /* close STDIN */
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
    // Ethernetデバイスを作成・登録します。
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
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
    int soc;
    struct ip_endpoint foreign;
    uint8_t buf[1024];

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    soc = udp_open();
    if (soc == -1) {
        errorf("udp_open() failure");
        return -1;
    }
    ip_endpoint_pton("192.0.2.1:10007", &foreign);
    // キーボードからの割り込みシグナルを受信するまで繰り返します。
    while (!terminate) {
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;
        }
        if (udp_sendto(soc, buf, strlen((char *)buf), &foreign) == -1) {
            errorf("udp_sendto() failure");
            break;
        }
    }
    udp_close(soc);
    // プロトコルスタックを停止します。
    cleanup();
    return 0;
}