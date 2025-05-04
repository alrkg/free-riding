#include "packet_modifier.h"

uint16_t PacketModifier::calcChecksum(uint16_t* data, int length) {
    uint32_t sum = 0;
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    if (length == 1) {
        sum += *(uint8_t*)data;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

// Receives a proxy IP, Port sorted in network byte order as a parameter
int PacketModifier::setFakeHeader(unsigned char* packet, int origLen, unsigned char* fakePacket, uint32_t proxyIp) {
    if (!packet) {
        fprintf(stderr, "[setFakeHeader] Null pointer passed for packet data.\n");
        return -1;
    }

    if (origLen < IP_HDR_LEN || origLen > MTU) {
        fprintf(stderr, "[setFakeHeader] Original packet length is too short\n");
        return -1;
    }

    if (!fakePacket) {
        fprintf(stderr, "[setFakeHeader] Null pointer passed for fakePacket.\n");
        return -1;
    }

    if ((sizeof(IpTcpHdr) + origLen) > MTU) {
        fprintf(stderr, "[setFakeHeader] Resulting packet size exceeds MTU\n");
        return -1;
    }

    IpTcpHdr fakeHdr{};
    TcpChecksumHdr tcpChecksumhdr{};
    memcpy(&fakeHdr.ipv4, packet, IP_HDR_LEN);

    //Set IP Header
    fakeHdr.ipv4.verIhl = 0x45;
    fakeHdr.ipv4.totalLen = htons(IP_HDR_LEN + TCP_HDR_LEN + origLen);
    fakeHdr.ipv4.proto = 0x06;
    fakeHdr.ipv4.checksum = 0;
    fakeHdr.ipv4.dstIp = proxyIp;
    fakeHdr.ipv4.checksum = calcChecksum(reinterpret_cast<uint16_t*>(&fakeHdr.ipv4), IP_HDR_LEN);

    //Set TCP Header
    fakeHdr.tcp.srcPort = 0x0000;
    fakeHdr.tcp.dstPort = 0x0000;
    fakeHdr.tcp.seqNum = 0x01;
    fakeHdr.tcp.ackNum = 0x01;
    fakeHdr.tcp.offsetFlags = htons(0x5000);
    fakeHdr.tcp.windowSize = 0xFFFF;
    fakeHdr.tcp.urgPointer = 0x0000;

    // Set TcpChecksum Header for TCP checksum calculation
    tcpChecksumhdr.pseudo.srcIp= fakeHdr.ipv4.srcIp;
    tcpChecksumhdr.pseudo.dstIp = fakeHdr.ipv4.dstIp;
    tcpChecksumhdr.pseudo.protocol = 0x06;
    tcpChecksumhdr.pseudo.length = htons(TCP_HDR_LEN);
    tcpChecksumhdr.tcp = fakeHdr.tcp;

    //Set TCP Checksum
    fakeHdr.tcp.checksum = calcChecksum(reinterpret_cast<uint16_t*>(&tcpChecksumhdr), PSEUDO_HDR_LEN + TCP_HDR_LEN);

    // Copy the new headers (Fake Header + Origin Packet) to the new packet
    memcpy(fakePacket, &fakeHdr, sizeof(IpTcpHdr));
    memcpy(fakePacket + sizeof(IpTcpHdr), packet, origLen);

    return (sizeof(IpTcpHdr) + origLen);
}
