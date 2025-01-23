#pragma once
#include <iostream>
#include "boost/asio.hpp"
struct Config
{
    bool is_server;
    boost::asio::ip::address address;
    unsigned short port;
    int threads;
    bool is_gvrf;
    int runs;
    int amount;
};

Config
create_config(int argc, char *argv[]);