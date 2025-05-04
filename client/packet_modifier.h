#pragma once
#include "net_headers.h"
#include <string.h>
#include <arpa/inet.h>
#include <stdexcept>

class PacketModifier{

public:
    static uint16_t calcChecksum(uint16_t* data, int length);
    static int setFakeHeader(unsigned char* packet, int origLen, unsigned char* fakePacket, uint32_t proxyIp);
};
