#include <kern/e1000.h>
#include <kern/eth.h>
#include <inc/string.h>
#include <kern/inet.h>
#include <inc/error.h>
#include <inc/assert.h>
#include <kern/arp.h>
#include <kern/ip.h>
#include <kern/traceopt.h>

// 10:00:00:11:11:11
static const uint8_t qemu_mac[6] = {0x10, 0x00, 0x00, 0x11, 0x11, 0x11};

const uint8_t *
get_my_mac(void) {
    return qemu_mac;
}

/**
 * @brief
 * Функция, которая упаковывает в один пакет слои: уровень Ethernet, уровень IP
 *
 * @param hdr указатель на фрейм Ethernet
 * @param data указатель на фрейм IP ИЛИ ARP
 * @param len число байт фрейма IP или ARP
 * 
 * @return возвращает статус отправки. Если статус отрицатен - отправка неудачна,
 *         так как очередь на сетевой карте уже заполнена.
 */
int
eth_send(struct eth_hdr *hdr, void *data, size_t len) {
    if (trace_packet_processing) cprintf("Sending Ethernet packet\n");
    assert(len <= ETH_MAX_PACKET_SIZE - sizeof(struct eth_hdr));

    char buf[ETH_MAX_PACKET_SIZE + 1];

    if (hdr->eth_type == JHTONS(ETH_TYPE_IP)) {
        struct ip_hdr *ip_header = &((struct ip_pkt *)data)->hdr;
        uint8_t *dmac = get_mac_by_ip(ip_header->ip_destination_address);
        if (dmac == NULL) {
            memset(hdr->eth_destination_mac, 0, 6);
        } else {
            memcpy(hdr->eth_destination_mac, get_mac_by_ip(ip_header->ip_destination_address), 6);
        }
    }
    hdr->eth_type = htons(hdr->eth_type);
    memcpy((void *)buf, (void *)hdr, sizeof(struct eth_hdr));
    memcpy((void *)buf + sizeof(struct eth_hdr), data, len);
    memcpy((void *)hdr->eth_source_mac, get_my_mac(), sizeof(hdr->eth_source_mac));

    // len - data length
    return e1000_transmit(buf, len + sizeof(struct eth_hdr));
}

/**
 * @brief
 * Функция, возвращающая определяющая тип входящих данных, по принадлежности к протоколу,
 * и запускающая процесс обработки данных. 
 * 
 * @param data указатель на заготовку для фрейма IP или ARP
 * 
 * @return возвращает количество байт прочитанного фрейма arp или ip, если обработка прошла успешно,
 *         иначе возвращает отрицательный результат.
 */
int
eth_recieve(void *data) {
    char buf[ETH_MAX_PACKET_SIZE + 1];
    struct eth_hdr hdr = {};
    // достаём очередной пакет из очереди
    int size = e1000_receive(buf);
    if (size <= 0) {
        return size;
    }

    if (trace_packet_processing) cprintf("Processing Ethernet packet\n");

    // ethernet frame filling
    memcpy((void *)&hdr, (void *)buf, sizeof(struct eth_hdr));
    hdr.eth_type = JNTOHS(hdr.eth_type);
    // ip or arp frame filling - payload
    memcpy(data, (void *)buf + sizeof(struct eth_hdr), size);

    if ((hdr.eth_type == ETH_TYPE_IP && ip_recv(data) >= 0)    ||
        (hdr.eth_type == ETH_TYPE_ARP && arp_resolve(data) >= 0))
    {
        return size;
    } else {
        return -E_BAD_ETH_TYPE;
    }
}
