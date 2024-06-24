#include <kern/ip.h>
#include <inc/string.h>
#include <kern/inet.h>
#include <inc/error.h>
#include <kern/eth.h>
#include <kern/icmp.h>
#include <inc/stdio.h>
#include <kern/traceopt.h>
#include <kern/arp.h>

/**
 * Функция-ответчик на ICMP-запрос.
 * Если её пингует незнакомец, то отправляем ARP-запрос
 */
int
icmp_echo_reply(struct ip_pkt *pkt) {
    if (trace_packet_processing) cprintf("Processing ICMP packet\n");
    
    struct icmp_pkt icmp_packet;
    struct ip_pkt result;

    int size = JNTOHS(pkt->hdr.ip_total_length) - IP_HEADER_LEN;
    memcpy((void *)&icmp_packet, (void *)pkt->data, size);
    
    struct icmp_hdr *hdr = &icmp_packet.hdr;

    if (hdr->msg_type != ECHO_REQUEST)
        return -E_UNS_ICMP_TYPE;
    if (hdr->msg_code != 0)
        return -E_INV_ICMP_CODE;

    hdr->msg_type = ECHO_REPLY;
    hdr->checksum = JHTONS(hdr->checksum);

    result.hdr.ip_protocol = IP_PROTO_ICMP;
    result.hdr.ip_source_address = JHTONL(MY_IP);

    uint8_t *dmac = get_mac_by_ip(pkt->hdr.ip_source_address);

    if (!dmac) {
        return arp_request(pkt);
    } else {
        result.hdr.ip_destination_address = pkt->hdr.ip_source_address;
    }

    memcpy((void *)result.data, (void *)&icmp_packet, size);
    return ip_send(&result, size);
}