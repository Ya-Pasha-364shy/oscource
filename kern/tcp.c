#include <kern/ip.h>
#include <inc/string.h>
#include <kern/inet.h>
#include <inc/error.h>
#include <inc/stdio.h>
#include <kern/tcp.h>
#include <kern/http.h>
#include <kern/traceopt.h>

struct tcp_virtual_channel tcp_vc[TCP_VC_NUM];

void
tcp_init_vc() {
    tcp_vc[0].state = LISTEN;
    tcp_vc[0].host_side.ip = MY_IP;
    tcp_vc[0].host_side.port = 80; // for browsers
    // tcp connection from host OS is expected
    tcp_vc[0].guest_side.ip = HOST_IP;
    tcp_vc[0].guest_side.port = 8080;
    for (int i = 1; i < TCP_VC_NUM; i++) {
        tcp_vc[i].state = LISTEN;
        tcp_vc[i].host_side.ip = MY_IP;
        tcp_vc[i].host_side.port = i;
        // tcp connection from host OS is expected
        tcp_vc[i].guest_side.ip = HOST_IP;
        tcp_vc[i].guest_side.port = 8080;
    }
}

int
tcp_send(struct tcp_virtual_channel* channel, struct tcp_pkt* pkt, size_t length) {
    if (trace_packet_processing) cprintf("Sending TCP packet\n");

    pkt->hdr.seq_num = JHTONL(channel->ack_seq.seq_num);
    pkt->hdr.ack_num = JHTONL(channel->ack_seq.ack_num);
    pkt->hdr.src_port = JHTONS(channel->host_side.port);
    pkt->hdr.dst_port = JHTONS(channel->guest_side.port);
    pkt->hdr.win_size = JHTONS(sizeof(channel->buffer));

    struct ip_pkt result = {};
    struct ip_hdr* hdr = &result.hdr;

    hdr->ip_protocol = IP_PROTO_TCP;
    hdr->ip_source_address = JHTONL(channel->host_side.ip);
    hdr->ip_destination_address = JHTONL(channel->guest_side.ip);

    size_t data_length = TCP_HEADER_LEN + length;
    pkt->hdr.checksum = 0;
    uint8_t buf[IP_DATA_LEN + 12] = {};
    memcpy((void *)buf + 12, (void*)pkt, data_length);
    memcpy((void *)buf, (void *)&hdr->ip_source_address, sizeof(hdr->ip_source_address));
    memcpy((void *)buf + 4, (void *)&hdr->ip_destination_address, sizeof(hdr->ip_destination_address));
    buf[8] = 0;
    buf[8 + 1] = hdr->ip_protocol;
    uint32_t network_data_length = JHTONS(data_length);
    memcpy((void *)buf + 8 + 2, (void *)&network_data_length, sizeof(network_data_length));
    pkt->hdr.checksum = JHTONS(JNTOHS(ip_checksum(buf, data_length + 12)) - channel->host_side.port);
    memcpy((void*)result.data, (void*)pkt, data_length);

    return ip_send(&result, data_length);
}

struct tcp_virtual_channel *
match_tcp_vc(struct tcp_pkt *pkt) {
    for (int i = 0; i < TCP_VC_NUM; i++) {
        if (tcp_vc[i].host_side.port == JNTOHS(pkt->hdr.dst_port)) {
            return &tcp_vc[i];
        }
    }
    return NULL;
}

int
match_listen_ip(struct tcp_virtual_channel *vc, uint32_t src_ip) {
    // always match
    return 1;
}

int
tcp_send_ack(struct tcp_virtual_channel *vc, uint8_t flags) {
    struct tcp_pkt ack_pkt = {};
    ack_pkt.hdr.data_offset = ((uint8_t)(TCP_HEADER_LEN >> 2) & 0xF);
    ack_pkt.hdr.flags = (uint32_t)flags | TH_ACK;
    int r = tcp_send(vc, &ack_pkt, 0);

    if (r == -1) {
        cprintf("tcp send error\n");
    }

    return r;
}

int
check_ack_seq(struct tcp_virtual_channel * vc, struct tcp_hdr ack_seq) {
    //cprintf("Ack=%u Seq=%u <== Ack=%u Seq=%u\n", vc->ack_seq.ack_num, vc->ack_seq.seq_num, (uint32_t)JNTOHL(ack_seq.ack_num), (uint32_t)JNTOHL(ack_seq.seq_num));

    return JNTOHL(ack_seq.seq_num) == vc->ack_seq.ack_num &&
           JNTOHL(ack_seq.ack_num) == vc->ack_seq.seq_num;
}

int
tcp_process(struct tcp_pkt *pkt, uint32_t src_ip, uint16_t tcp_data_len) {
    if (trace_packet_processing) cprintf("Processing TCP packet\n");
    struct tcp_virtual_channel * vc = match_tcp_vc(pkt);
    if (vc == NULL) {
        cprintf("No TCP VC match for packet\n");
        goto error;
    }
    switch(vc->state) {
    case CLOSED:
        // not implemented
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    case LISTEN:
        if ((uint32_t)pkt->hdr.flags & TH_SYN) {
            if (match_listen_ip(vc, src_ip)) {
                // trivial seq num
                vc->ack_seq.seq_num = JNTOHL(pkt->hdr.seq_num);
                vc->guest_side.ip = src_ip;
                vc->guest_side.port = JNTOHS(pkt->hdr.src_port);
                vc->ack_seq.ack_num = JNTOHL(pkt->hdr.seq_num) + 1;
                tcp_send_ack(vc, TH_SYN);

                vc->ack_seq.seq_num++;
                vc->state = SYN_RECEIVED;
            } else {
                cprintf("Source IP");
                num2ip(src_ip);
                cprintf("didn't match listen IP");
                num2ip(vc->guest_side.ip);
                cprintf("\n");
                goto error;
            }
        } else {
            cprintf("SYN flag is not provided\n");
            goto error;
        }
        break;
    case SYN_SENT:
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    case SYN_RECEIVED:
        if ((uint32_t)pkt->hdr.flags & TH_ACK) {
            if (src_ip != vc->guest_side.ip) {
                cprintf("Wrong IP -");
                num2ip(src_ip);
                cprintf(" is not");
                num2ip(vc->guest_side.ip);
                cprintf("\n");
                goto error;
            }
            if (!check_ack_seq(vc, pkt->hdr)) {
                cprintf("Wrond ack seq\n");
                goto error;
            }
            vc->state = ESTABLISHED;
        } else {
            cprintf("ACK flag is not provided\n");
            goto error;
        }
        break;
    case ESTABLISHED:
        if ((uint32_t)pkt->hdr.flags & TH_ACK) {
            if (src_ip != vc->guest_side.ip) {
                cprintf("Wrong IP -");
                num2ip(src_ip);
                cprintf(" is not");
                num2ip(vc->guest_side.ip);
                cprintf("\n");
                goto error;
            }
            if (!check_ack_seq(vc, pkt->hdr)) {
                cprintf("Wrond ack seq\n");
                goto error;
            }
            if (vc->data_len + tcp_data_len >= TCP_WINDOW_SIZE) {
                cprintf("Buffer overflow\n");
                goto error;
            }
            memcpy((void *)vc->buffer + vc->data_len, (void *)pkt->data, tcp_data_len);
            vc->data_len += tcp_data_len;
            vc->ack_seq.ack_num += tcp_data_len;

            if ((uint32_t)pkt->hdr.flags & TH_PSH) {
                size_t reply_len = 0;
                struct tcp_pkt data_pkt = {};
                data_pkt.hdr.data_offset = ((uint8_t)(TCP_HEADER_LEN >> 2) & 0xF);
                data_pkt.hdr.flags = TH_ACK | TH_PSH | TH_FIN;
                http_parse((char *)vc->buffer, vc->data_len, (char *)&data_pkt.data, &reply_len);
                int r = tcp_send(vc, &data_pkt, reply_len);
                if (r == -1) {
                    cprintf("tcp send error\n");
                    goto error;
                }
                vc->ack_seq.seq_num += reply_len + 1; // +1 - because of FIN
                vc->data_len = 0; // because of PSH
                vc->state = CLOSE_WAIT;
            } else if (tcp_data_len) {
                tcp_send_ack(vc, 0);
            }
        } else {
            cprintf("ACK flag is not provided\n");
            goto error;
        }
        break;
    case FIN_WAIT_1:
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    case CLOSING:
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    case FIN_WAIT_2:
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    case TIME_WAIT:
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    case CLOSE_WAIT:
        if ((uint32_t)pkt->hdr.flags & TH_ACK) {
            if ((uint32_t)pkt->hdr.flags & TH_FIN) {
                if (src_ip != vc->guest_side.ip) {
                    cprintf("Wrong IP -");
                    num2ip(src_ip);
                    cprintf(" is not");
                    num2ip(vc->guest_side.ip);
                    cprintf("\n");
                    goto error;
                }
                if (!check_ack_seq(vc, pkt->hdr)) {
                    cprintf("Wrond ack seq\n");
                    goto error;
                }
                vc->ack_seq.ack_num += 1; // new ACK answer of zero lenght
                tcp_send_ack(vc, 0);
                vc->state = LISTEN;
            }
        } else {
            cprintf("ACK flag is not provided\n");
            goto error;
        }
        break;
    case LAST_ACK:
        cprintf("Unimplemented state - %d\n", vc->state);
        break;
    default:
        cprintf("Impossible state - %d\n", vc->state);
        break;
    }

    return 0;

error:
    cprintf("Error on state %d\n", vc->state);
    return -1;
}

int
tcp_recv(struct ip_pkt* pkt) {
    if (JNTOHS(pkt->hdr.ip_total_length) - IP_HEADER_LEN < TCP_HEADER_LEN) {
        cprintf("IP packet too short for TCP header\n");
        return -1;
    }
    struct tcp_pkt tcp_pkt;
    memcpy((void *)&tcp_pkt, (void *)pkt->data, JNTOHS(pkt->hdr.ip_total_length) - IP_HEADER_LEN);
    return tcp_process(&tcp_pkt, JNTOHL(pkt->hdr.ip_source_address), JNTOHS(pkt->hdr.ip_total_length) - IP_HEADER_LEN - TCP_HEADER_LEN);
}
