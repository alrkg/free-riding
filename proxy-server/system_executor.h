#pragma once
#include <string>
#include <arpa/inet.h>
#include <stdexcept>

class SystemExecutor{
public:
    static std::string exec(const std::string& cmd);
    static std::string execPing(const std::string& ip);
};
