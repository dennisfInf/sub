#include "config.h"
#include "boost/asio.hpp"
void print_usage()
{
    std::cerr << "Usage: gvrf --role <'client' or 'server'> --address <address> --port <port> --threads <threads> --amount <amount> --runs <runs>\n"
              << "Example:\n"
              << "    gvrf --role server --address 0.0.0.0 --port 8080 --threads 1 --runs 50 --amount 50 \n";
    exit(EXIT_FAILURE);
}
void check_for_duplicate_parameter(bool b, std::string s)
{
    if (b)
    {
        std::cout << "parameter " << s << " was specified more than once" << std::endl;
        print_usage();
    }
}

void incorrect_value(std::string s)
{
    std::cout << "incorrect value specified for parameter " << s << std::endl;
    print_usage();
}

Config
create_config(int argc, char *argv[])
{
    if (argc != 13)
    {
        print_usage();
    }
    Config conf;
    std::vector<bool> assigned(5);
    for (int i = 1; i < 13; i += 2)
    {
        std::string parameter = std::string(argv[i]);
        if (parameter == "--role")
        {
            check_for_duplicate_parameter(assigned[0], parameter);
            std::string value = argv[i + 1];
            if (value == "server")
            {
                conf.is_server = true;
            }
            else if (value == "client")
            {
                conf.is_server = false;
            }
            else
            {
                incorrect_value(parameter);
            }
        }
        else if (parameter == "--address")
        {
            check_for_duplicate_parameter(assigned[1], argv[i]);
            conf.address = boost::asio::ip::make_address(argv[i + 1]);
        }
        else if (parameter == "--port")
        {
            check_for_duplicate_parameter(assigned[2], argv[i]);
            conf.port = static_cast<unsigned short>(std::atoi(argv[i + 1]));
        }
        else if (parameter == "--threads")
        {
            check_for_duplicate_parameter(assigned[3], argv[i]);
            conf.threads = std::max<int>(1, std::atoi(argv[i + 1]));
        }
        else if (parameter == "--amount")
        {
            conf.amount = std::atoi(argv[i + 1]);
        }
        else if (parameter == "--runs")
        {
            conf.runs = std::atoi(argv[i + 1]);
        }
        else
        {
            std::cout << "unknown parameter" << std::endl;
            print_usage();
        };
    }
    return conf;
}