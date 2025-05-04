#pragma once
#include <regex>
#include <stdint.h>

class NetUtils
{
public:
    static bool isValidMac(const std::string& ip);
    static int strToMacAddr(const std::string& macStr, uint8_t mac[6]);
};
