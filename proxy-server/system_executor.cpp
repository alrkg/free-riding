#include "system_executor.h"

std::string SystemExecutor::exec(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen() failed");
    }

    std::string result;
    char buffer[1024];

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result.append(buffer);
    }

    if (pclose(pipe) == -1) {
        throw std::runtime_error("pclose() failed");
    }

    return result;
}


std::string SystemExecutor::execPing(const std::string& ip) {
    in_addr addr;
    if (inet_pton(AF_INET, ip.c_str(), &addr) <= 0) {
        throw std::invalid_argument("Invalid IP address provided: " + ip);
    }

    std::string cmd = "ping -c 1 " + ip;
    return exec(cmd);
}
