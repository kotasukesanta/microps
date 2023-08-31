#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

// ICMPの入力関数です。
void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    debugdump(data, len);
}

// ICMPを初期化します。
int
icmp_init(void)
{
    // Exercise 9-4: ICMPの入力関数（icmp_input）をIPに登録
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}