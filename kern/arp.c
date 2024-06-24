#include <inc/stdio.h>
#include <inc/string.h>
#include <kern/arp.h>
#include <kern/eth.h>
#include <inc/error.h>
#include <kern/inet.h>
#include <kern/traceopt.h>

static struct arp_cache_table arp_table[ARP_TABLE_MAX_SIZE];

/**
 * Перебирает ARP-таблицу в поисках следующего элемента.
 */
uint8_t *
get_mac_by_ip(uint32_t ip) {
    struct arp_cache_table *entry;
    for (int i = 0; i < ARP_TABLE_MAX_SIZE; i++) {
        entry = &arp_table[i];
        if (entry->source_ip == ip) {
            return entry->source_mac;
        }
    }
    return NULL;
}

/**
 * Хардкодим запись в ARP-таблицу об br0 интерфейсе - мастере.
 * А также подготавливаем слоты для других записей.
*/
void
initialize_arp_table() {
    struct arp_cache_table *entry;
    entry = &arp_table[ARP_TABLE_MAX_SIZE - 1]; // it shall be just default MAC

    entry->source_ip = JHTONL(HOST_IP);
    // aa:aa:aa:aa:aa:aa - mac address of br0 interface
    uint8_t mac[6] = {0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa};
    memcpy(entry->source_mac, mac, 6);
    entry->state = STATIC_STATE;

    // подготавливаем все остальные записи
    for (int i = 1; i < ARP_TABLE_MAX_SIZE; i++) {
        entry = &arp_table[i];
        entry->state = FREE_STATE;
    }
}

/**
 * Обновляет ARP-таблицу по событию получения нового ARP-запроса (от нового абонента)
 */
int
update_arp_table(struct arp_hdr *arp_header) {
    int i;
    struct arp_cache_table *entry;

    for (i = 0; i < ARP_TABLE_MAX_SIZE; i++) {
        entry = &arp_table[i];
        // если запись свободна, то запоминаем в неё нового абонента
        if (entry->state == FREE_STATE) {
            entry->source_ip = arp_header->source_ip;
            memcpy(entry->source_mac, arp_header->source_mac, 6);
            entry->state = DYNAMIC_STATE;
            return 0;
        }

        if (entry->source_ip == arp_header->source_ip) {
            if (entry->state == DYNAMIC_STATE) {
                memcpy(entry->source_mac, arp_header->source_mac, 6);
            }
            break;
        }
    }

    return 0;
}

/**
 * Отсылает ARP-запрос, когда необходимо
 */
int
arp_request(struct ip_pkt *reply_packet) {
    if (trace_packet_processing) cprintf("Sending ARP-request\n");

    struct eth_hdr ethernet_header;
    struct arp_hdr arp_request;

    uint8_t *jos_mac = get_mac_by_ip(MY_IP);

    memcpy(ethernet_header.eth_source_mac, jos_mac, 6);
    memset(ethernet_header.eth_destination_mac, 0, 6);
    ethernet_header.eth_type = JHTONS(ETH_TYPE_ARP);

    memcpy(arp_request.source_mac, jos_mac, 6);

    arp_request.source_ip = reply_packet->hdr.ip_source_address;
    // broadcast address must be here:
    arp_request.target_ip = JHTONL(BROADCAST_IP);
    arp_request.protocol_type = JNTOHS(ARP_IPV4);
    arp_request.hardware_type = JNTOHS(ARP_ETHERNET);
    arp_request.opcode = JNTOHS(ARP_REQUEST);

    int status = eth_send(&ethernet_header, &arp_request, sizeof(struct arp_hdr));

    if (status < 0) {
        cprintf("Error attempting arp response.");
        return -1;
    }
    return 0;
}

/**
 * Отвечаем на ARP-запрос, посылаем ARP-reply (ответ)
 */
int
arp_reply(struct arp_hdr *arp_header) {
    if (trace_packet_processing) cprintf("Sending ARP reply\n");

    struct eth_hdr ethernet_header;

    arp_header->opcode = ARP_REPLY;
    memcpy(arp_header->target_mac, arp_header->source_mac, 6);
    arp_header->target_ip = arp_header->source_ip;
    memcpy(arp_header->source_mac, get_my_mac(), 6);
    arp_header->source_ip = JHTONL(MY_IP);

    arp_header->opcode = JHTONS(arp_header->opcode);
    arp_header->hardware_type = JHTONS(arp_header->hardware_type);
    arp_header->protocol_type = JHTONS(arp_header->protocol_type);

    memcpy(ethernet_header.eth_destination_mac, arp_header->target_mac, 6);
    ethernet_header.eth_type = JHTONS(ETH_TYPE_ARP);

    int status = eth_send(&ethernet_header, arp_header, sizeof(struct arp_hdr));
    if (status < 0) {
        cprintf("Error attempting arp response.");
        return -1;
    }
    return 0;
}

int
arp_resolve(void *data) {
    if (trace_packet_processing) cprintf("Resolving ARP\n");
    struct arp_hdr *arp_header;

    arp_header = (struct arp_hdr *)data;

    arp_header->hardware_type = JNTOHS(arp_header->hardware_type);
    arp_header->protocol_type = JNTOHS(arp_header->protocol_type);
    arp_header->opcode        = JNTOHS(arp_header->opcode);
    arp_header->target_ip     = JNTOHL(arp_header->target_ip);

    if (arp_header->hardware_type != ARP_ETHERNET) {
        cprintf("Error! Only ethernet is supporting.");
        return -1;
    }
    if (arp_header->protocol_type != ARP_IPV4) {
        cprintf("Error! Only IPv4 is supported.");
        return -1;
    }

    int status = update_arp_table(arp_header);
    if (status < 0) {
        cprintf("ARP table already filled !\n");
    }
    if (arp_header->target_ip != MY_IP) {
        cprintf("Keep silence !\n");
        return -1;
    }
    if (arp_header->opcode != ARP_REQUEST) {
        cprintf("Keep silence !\n");
        return -1;
    }

    return arp_reply(arp_header);
}
