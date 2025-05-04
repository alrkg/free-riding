#include "net_utils.h"

bool NetUtils::isValidMac(const std::string& mac) {
    std::regex pattern("^([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})$");
    if (!std::regex_match(mac, pattern)) return false;
    return true;
}

int NetUtils::strToMacAddr(const std::string& macStr, uint8_t mac[6]) {
    if(!isValidMac(macStr)) return -1;
    for (int i = 0; i < 6; ++i) {
        mac[i] = static_cast<uint8_t>(std::stoi(macStr.substr(i*3, 2), nullptr, 16));
    }
    return 0;
}
