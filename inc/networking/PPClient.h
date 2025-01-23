#pragma once
#include "networking/beast/client.h"
#include "crypto/privacy_pass/client.h"
#include "config.h"

namespace PrivacyPass
{
    struct ClientBenchmarks
    {
        std::chrono::duration<double> total_signing;
        std::chrono::duration<double> gen_and_blind_token;
        std::chrono::duration<double> verify_dleq;
        std::chrono::duration<double> total_expand;
        std::chrono::duration<double> total_client_generate;

        std::chrono::duration<double> total_redeem_token;
        uint32_t signing_request_size;
        uint32_t signing_response_size;
        uint32_t redemption_request_size;
        uint32_t token_size;
    };

    class WebClient
    {
    public:
        WebClient(Config &conf);
        void get_tokens(int amount);
        void redeem_token();
        void get_and_redeem_tokens(int amount, int runs);

    private:
        http::request<http::vector_body<uint8_t>> create_request(std::vector<uint8_t> &body, std::string &target);
        Client client;
        net::io_context ioc;
        ssl::context ctx;
        std::string address;
        std::string port;
        EpGroup::EP c_sk;
        ClientBenchmarks total_benchmarks;
        ClientBenchmarks one_run_benchmarks;
    };

};
