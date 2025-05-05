#include <iostream>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "net_headers.h"
#include "packet_modifier.h"

#define BUFFER_SIZE 4096

bool parse(int argc, char* argv[], in_addr& proxyIp) {
    if (argc != 2) {
        fprintf(stderr, "syntax : free-riding <Proxy ip>\n");
        fprintf(stderr, "sample : free-riding 128.123.0.1\n");
        return false;
    }

    if (inet_pton(AF_INET, argv[1], &proxyIp) != 1) {
        fprintf(stderr, "Invalid IP address");
        return false;
    }

    return true;
}

void setupNFQueue() {
    system("sudo iptables -F");
    system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
}

void resetNFQueue() {
    system("sudo iptables -F");
}

u_int32_t returnId(struct nfq_data *tb)
{
    nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    return ph ? ntohl(ph->packet_id) : 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    u_int32_t id = returnId(nfa);
    unsigned char *pkt_data;
    in_addr* proxyIp = static_cast<in_addr*>(data);
    int len = nfq_get_payload(nfa, &pkt_data);

    if (len >= 0) {
        unsigned char fakePacket[BUFFER_SIZE];
        int newLen = PacketModifier::setFakeHeader(pkt_data, len, fakePacket, proxyIp->s_addr);
        if (newLen != -1) return nfq_set_verdict(qh, id, NF_ACCEPT, newLen, fakePacket);
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char* argv[])
{
    in_addr proxyIp;
    if(!parse(argc, argv, proxyIp)) exit(1);
    setupNFQueue();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd, rv;
    char buf[BUFFER_SIZE];

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, &proxyIp);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    while(1) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }

        if (rv < 0 && errno == ENOBUFS) {
            fprintf(stderr, "losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    resetNFQueue();

    return 0;
}
