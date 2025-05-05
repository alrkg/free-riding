#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include "net_headers.h"
#include "gateway_info.h"

struct Gateway {
    std::string interface;
    uint8_t macAddr[ETH_ADDR_LEN];
};

bool parse(int argc, char* argv[], Gateway& gateway) {
    if (argc != 2) {
        fprintf(stderr, "syntax: proxy-server <interface>\n");
        fprintf(stderr, "sample: proxy-server wlan0\n");
        return false;
    }
    gateway.interface = argv[1];
    return true;
}

int main(int argc, char* argv[])
{
    Gateway gateway;
    if (!parse(argc, argv, gateway)) {
        fprintf(stderr, "Error: Invalid number of arguments.\n");
        exit(1);
    }

    try {
        GatewayInfo::getGatewayMacAddr(gateway.interface, gateway.macAddr);
    } catch (const std::exception& e) {
        fprintf(stderr, "%s\n", e.what());
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(gateway.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", gateway.interface.c_str(), errbuf);
        exit(1);
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        if (header->len > sizeof(EthIpTcpHdr)) {
            EthIpTcpHdr* ethIpTcpHdr = (EthIpTcpHdr*)(packet);
            if (!(ntohs(ethIpTcpHdr->eth.ethType) == 0x0800)) continue;
            if (!(ethIpTcpHdr->ipv4.proto == 0x06)) continue;

            if (htons(ethIpTcpHdr->tcp.dstPort) == 0x000) {
                char buffer[BUFSIZ];
                memcpy(buffer, packet, ETH_HDR_LEN);
                memcpy(buffer + ETH_HDR_LEN, packet + sizeof(EthIpTcpHdr), header->len - sizeof(EthIpTcpHdr));

                EthHdr* eth = (EthHdr*)buffer;
                for(int i = 0; i < 6; ++i) eth->dstMac[i] = gateway.macAddr[i];

                pcap_sendpacket(pcap, (const u_char*)buffer, header->len - sizeof(IpTcpHdr));
            }
        }
    }

    return 0;
}
