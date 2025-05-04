#include "gateway_info.h"

std::string GatewayInfo::getGatewayIp(const std::string &interface) {
    std::regex pattern("^[a-zA-Z0-9_.-]+$");
    if (!std::regex_match(interface, pattern)) {
        throw std::invalid_argument("Invalid network interface format: " + interface);
    }

    std::string gatewayIpCmd = "ip route | grep default | grep " + interface + " | awk '{print $3}'";
    std::string gatewayIp = SystemExecutor::exec(gatewayIpCmd);
    gatewayIp.erase(gatewayIp.find_last_not_of("\n\r\t") + 1);

    if (gatewayIp.empty()) {
        throw std::runtime_error("No default gateway found for interface: " + interface);
    }

    in_addr addr;
    if (inet_pton(AF_INET, gatewayIp.c_str(), &addr) <= 0) {
        throw std::invalid_argument("Invalid IP address format: " + gatewayIp);
    }

    return gatewayIp;
}

// Returns the MAC address of the gateway as a string.
std::string GatewayInfo::getGatewayMacStr(const std::string& interface) {
    std::string gatewayIp = getGatewayIp(interface);
    SystemExecutor::execPing(gatewayIp);

    std::string gatewayMacCmd = "ip neigh | grep -E '^" + gatewayIp + "\\s' | awk '{print $5}'";
    std::string gatewayMac = SystemExecutor::exec(gatewayMacCmd);
    gatewayMac.erase(gatewayMac.find_last_not_of("\n\r\t") + 1);

    if (gatewayMac.empty()) {
        throw std::runtime_error("No MAC address found for gateway IP: " + gatewayIp);
    }
    if (!NetUtils::isValidMac(gatewayMac)) {
        throw std::invalid_argument("Invalid MAC address format for gateway IP: " + gatewayIp);
    }

    return gatewayMac;
}

// Stores the gateway's MAC address in a 6-byte array.
void GatewayInfo::getGatewayMacAddr(const std::string& interface, uint8_t mac[6]) {
    std::string macStr = getGatewayMacStr(interface);
    NetUtils::strToMacAddr(macStr, mac);
}


