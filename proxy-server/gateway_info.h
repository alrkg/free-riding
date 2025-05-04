#pragma once
#include <string>
#include <algorithm>
#include <stdexcept>
#include <regex>
#include "system_executor.h"
#include "net_utils.h"

class GatewayInfo
{
public:
    static std::string getGatewayIp(const std::string& interface);
    static std::string getGatewayMacStr(const std::string& interface);
    static void getGatewayMacAddr(const std::string& interface, uint8_t mac[6]);
};
