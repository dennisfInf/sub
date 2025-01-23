#pragma once
#include "networking/beast/client.h"
#include "crypto/gvrfs/client.h"
#include "config.h"
#include "crypto/bilinear_group/group.h"

namespace GVRF
{
    struct ClientBenchmarks
    {
        std::chrono::duration<double> generate;
        std::chrono::duration<double> expand;
        std::chrono::duration<double> verify;
        std::chrono::duration<double> generate_client;
        uint32_t redemption_request_size;
        uint32_t token_size;
        uint32_t generate_req;
        uint32_t generate_res;
    };

    class WebClient
    {
    public:
        WebClient(Config &conf, int *l);
        void generate();
        void expand(int &amount);
        void verify();
        void get_and_redeem_tokens(int amount, int runs);

    private:
        http::request<http::vector_body<uint8_t>> create_request(std::vector<uint8_t> &body, std::string &target);
        Client client;
        std::vector<Eval> evals;
        net::io_context ioc;
        ssl::context ctx;
        std::string address;
        std::string port;
        ClientBenchmarks total_benchmarks;
        ClientBenchmarks one_run_benchmarks;
    };

};
