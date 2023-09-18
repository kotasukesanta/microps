#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_raise_event();
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
    struct ip_endpoint local, foreign;
    int soc;
    uint8_t buf[2048];
    ssize_t ret;

    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    ip_endpoint_pton("192.0.2.2:7", &local);
    ip_endpoint_pton("192.0.2.1:10007", &foreign);
    soc = tcp_open_rfc793(&local, &foreign, 1);
    if (soc == -1) {
        errorf("tcp_open_rfc793() failure");
        return -1;
    }
    // キーボードからの割り込みシグナルを受信するまで繰り返します。
    while (!terminate) {
        ret = tcp_receive(soc, buf, sizeof(buf));
        if (ret <= 0) {
            break;
        }
        hexdump(stderr, buf, ret);
        tcp_send(soc, buf, ret);
    }
    tcp_close(soc);
    // プロトコルスタックを停止します。
    cleanup();
    return 0;
}