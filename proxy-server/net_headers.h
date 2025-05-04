#pragma once
#include <stdint.h>

#define ETH_ADDR_LEN 6
#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define TCP_HDR_LEN 20
#define PSEUDO_HDR_LEN 12
#define MTU 1500

#pragma pack(push, 1)
struct EthHdr
{
    uint8_t dstMac[ETH_ADDR_LEN];
    uint8_t srcMac[ETH_ADDR_LEN];
    uint16_t ethType;
};

struct Ipv4Hdr
{
    uint8_t verIhl;
    uint8_t dscpEcn;
    uint16_t totalLen;
    uint16_t id;
    uint16_t flagsOffset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t checksum;
    uint32_t srcIp;
    uint32_t dstIp;
};

struct TcpHdr
{
    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint16_t offsetFlags;
    uint16_t windowSize;
    uint16_t checksum;
    uint16_t urgPointer;
};

struct PseudoHdr
{
    uint32_t srcIp;
    uint32_t dstIp;
    uint8_t reversed = 0;
    uint8_t protocol;
    uint16_t length;
};

struct EthIpTcpHdr
{
    EthHdr eth;
    Ipv4Hdr ipv4;
    TcpHdr tcp;
};

struct IpTcpHdr
{
    Ipv4Hdr ipv4;
    TcpHdr tcp;
};

struct TcpChecksumHdr
{
    PseudoHdr pseudo;
    TcpHdr tcp;
};
#pragma pack(pop)
