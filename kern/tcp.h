#ifndef JOS_KERN_TCP_H
#define JOS_KERN_TCP_H

#include <inc/types.h>
#include <kern/ip.h>

struct tcp_hdr {
    uint16_t src_port; // auto in __tcp_send
    uint16_t dst_port; // auto in __tcp_send
    uint32_t seq_num; // auto in __tcp_send
    uint32_t ack_num; // auto in __tcp_send
    uint8_t ns : 1,
            reserved : 3,
            data_offset : 4; // <data_offset><reserved><ns> field
    uint8_t flags;
    uint16_t win_size; // auto in __tcp_send
    uint16_t checksum; // auto in __tcp_send
    uint16_t urgent;
} __attribute__((packed));

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_NS  0x100

#define TCP_HEADER_LEN sizeof(struct tcp_hdr)
#define TCP_DATA_LEN (IP_DATA_LEN - TCP_HEADER_LEN)
#define TCP_WINDOW_SIZE TCP_DATA_LEN * 10

struct tcp_pkt {
    struct tcp_hdr hdr;
    uint8_t data[TCP_DATA_LEN];
} __attribute__((packed));

enum tcp_state {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    CLOSING,
    FIN_WAIT_2,
    TIME_WAIT,
    CLOSE_WAIT,
    LAST_ACK
};

struct tcp_endpoint {
    uint32_t ip;
    uint16_t port;
};

struct tcp_ack_seq {
    uint32_t seq_num;
    uint32_t ack_num;
};

struct tcp_virtual_channel {
    enum tcp_state state;
    struct tcp_endpoint host_side;
    struct tcp_endpoint guest_side;
    struct tcp_ack_seq ack_seq;
    uint8_t buffer[TCP_WINDOW_SIZE];
    uint32_t data_len;
};

#define TCP_VC_NUM 64

void tcp_init_vc();
int tcp_send(struct tcp_virtual_channel* channel, struct tcp_pkt* pkt, size_t length);
int tcp_recv(struct ip_pkt* pkt);

#endif
