#include "networking/PPClient.h"
#include "networking/certs/root_certificates.hpp"
#include "crypto/ep_group/deserializer.h"
#include "crypto/ep_group/serializer.h"
namespace PrivacyPass
{
    WebClient::WebClient(Config &conf) : ctx(ssl::context::tlsv13_client)
    {
        ctx.use_certificate_file("./cert/localhost.crt", boost::asio::ssl::context_base::file_format::pem);
        // ctx.set_verify_mode(ssl::verify_peer);
        //  load_root_certificates(ctx);
        ctx.set_verify_mode(ssl::verify_none);
        this->port = std::to_string(conf.port);
        this->address = conf.address.to_string();
        std::string target = "/GetCommitedSK";
        std::cout
            << "starting client connnecting to" << conf.address.to_string() << ":" << conf.port << std::endl;
        std::vector<uint8_t> buf;

        http::request<http::vector_body<uint8_t>> req = create_request(buf, target);

        auto const session = std::make_shared<NetworkingClient::session>(
            net::make_strand(ioc),
            ctx, req);

        session->run(address.c_str(), port.c_str());
        ioc.run();
        EpGroup::Deserializer des(session->res_.body());
        des >> c_sk;
    };

    http::request<http::vector_body<uint8_t>> WebClient::create_request(std::vector<uint8_t> &body, std::string &target)
    {
        http::request<http::vector_body<uint8_t>> req_;
        req_.method(http::verb::post);
        req_.target(target);
        req_.set(http::field::host, address);
        req_.body() = std::move(body);
        req_.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        req_.prepare_payload();
        return req_;
    }

    void WebClient::get_tokens(int amount)
    {
        auto start = std::chrono::high_resolution_clock::now();

        std::vector<Token> tokens(amount);
        std::vector<EpGroup::EP> P_s(amount);
        auto start_gen_tokens = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < amount; i++)
        {
            tokens[i] = client.GetAndBlindToken();
            P_s[i] = tokens[i].bt.T_hat;
        }

        auto end_gen_tokens = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time_gen_tokens = end_gen_tokens - start_gen_tokens;
        one_run_benchmarks.gen_and_blind_token += elapsed_time_gen_tokens;
        std::vector<uint8_t> buf;
        EpGroup::Serializer ser(buf);
        ser << P_s;
        std::string target = "/PPTokenSign";
        http::request<http::vector_body<uint8_t>> req = create_request(buf, target);
        ioc.reset();
        auto const session = std::make_shared<NetworkingClient::session>(
            net::make_strand(ioc),
            ctx, req);
        one_run_benchmarks.signing_request_size = req.body().size();
        session->run(address.c_str(), port.c_str());
        ioc.run();
        DLEQ::Proof proof;
        one_run_benchmarks.signing_response_size = session->res_.body().size();

        EpGroup::Deserializer des(session->res_.body());
        des >> proof.c;
        des >> proof.s;
        std::vector<EpGroup::EP> signed_tokens;
        des >> signed_tokens;
        bool verified;
        auto start_dleq = std::chrono::high_resolution_clock::now();
        if (amount > 1)
        {
            verified = client.BatchVerify(proof, c_sk, P_s, signed_tokens);
        }
        else
        {
            verified = client.Verify(proof, c_sk, P_s[0], signed_tokens[0]);
        }
        auto end_dleq_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> end_dleq = end_dleq_time - start_dleq;
        one_run_benchmarks.verify_dleq += end_dleq;
        auto start_unblind = std::chrono::high_resolution_clock::now();
        ;
        if (verified)
        {
            for (int i = 0; i < amount; i++)
            {
                client.AddToken({tokens[i].t, client.Unblind(signed_tokens[i], tokens[i].bt.r)});
            }
        }
        else
        {
            std::cout << "Client: DLEQ Proof Verification failed." << std::endl;
            exit(1);
        }
        auto end_unblind = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> total_unblind = end_unblind - start_unblind;

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time = end - start;
        one_run_benchmarks.total_signing += elapsed_time;
        one_run_benchmarks.total_client_generate += total_unblind + end_dleq + elapsed_time_gen_tokens;
    }
    void WebClient::redeem_token()
    {
        auto start_expand = std::chrono::high_resolution_clock::now();

        std::string target = "/PPTokenRedeem";
        std::vector<uint8_t> R;

        // Convert the string to uint8_t and insert into the vector
        for (char c : target)
        {
            R.push_back(static_cast<uint8_t>(c));
        }
        size_t length = 0;
        while (address[length] != '\0')
        {
            ++length;
        }

        for (size_t i = 0; i < length; ++i)
        {
            R.push_back(static_cast<uint8_t>(address[i]));
        }
        ClientRedeem cr = client.Redeem(R);
        auto end_expand = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time_exp = end_expand - start_expand;
        one_run_benchmarks.total_expand += elapsed_time_exp;
        std::vector<uint8_t> buffer;
        auto start_verify = std::chrono::high_resolution_clock::now();

        EpGroup::Serializer ser(buffer);
        ser << cr.mac;
        ser << cr.t;
        this->one_run_benchmarks.token_size = buffer.size();
        http::request<http::vector_body<uint8_t>> req = create_request(buffer, target);
        ioc.reset();
        auto const session = std::make_shared<NetworkingClient::session>(
            net::make_strand(ioc),
            ctx, req);
        one_run_benchmarks.redemption_request_size = req.body().size();
        session->run(address.c_str(), port.c_str());
        ioc.run();
        bool accepted = session->res_.body()[0];
        if (!accepted)
        {
            std::cout << "token was not successfully redeemed" << std::endl;
            exit(1);
        }
        auto end_verify = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time = end_verify - start_verify;
        one_run_benchmarks.total_redeem_token += elapsed_time;
    }

    void print_benchmarks(int amount, int runs, ClientBenchmarks benchmarks)
    {
        std::cout << "Average total time of AT.Generate(): ";
        std::cout << benchmarks.total_signing.count() / runs << " seconds" << std::endl;
        std::cout << "From that " << benchmarks.gen_and_blind_token.count() / runs << " seconds for Token generation (GenToken() & Blind())" << std::endl;
        std::cout << "and " << benchmarks.verify_dleq.count() / runs << " seconds for verifying the DLEQ Proof" << std::endl;
        std::cout << "total client comp: " << benchmarks.total_client_generate.count() / runs << " seconds " << std::endl;
        std::cout << std::endl;
        std::cout << "Average time for redeeming " << amount << " tokens with AT.Verify()" << benchmarks.total_redeem_token.count() / (runs) << " seconds" << std::endl;
        std::cout << "Average time for redeeming one token with AT.Verify()" << benchmarks.total_redeem_token.count() / (runs * amount) << " seconds" << std::endl;
        std::cout << "Average time for expanding" << benchmarks.total_expand.count() / (runs) << " seconds" << std::endl;

        std::cout << std::endl;
        std::cout << "Payload sizes of the HTTP packets in bytes:" << std::endl;
        std::cout << "Signing Request (Client->Server): " << benchmarks.signing_request_size << std::endl;
        std::cout << "Signing Response (Server->Client): " << benchmarks.signing_response_size << std::endl;
        std::cout << "Redemption Request (Client->Server): " << benchmarks.redemption_request_size << std::endl;
        std::cout << "Token size: " << benchmarks.token_size << std::endl;
    }

    void add_benchmarks(ClientBenchmarks &total_benchmarks, ClientBenchmarks &one_run)
    {
        total_benchmarks.gen_and_blind_token += one_run.gen_and_blind_token;
        total_benchmarks.redemption_request_size = one_run.redemption_request_size;
        total_benchmarks.signing_request_size = one_run.signing_request_size;
        total_benchmarks.signing_response_size = one_run.signing_response_size;
        total_benchmarks.total_redeem_token += one_run.total_redeem_token;
        total_benchmarks.total_expand += one_run.total_expand;
        total_benchmarks.total_signing += one_run.total_signing;
        total_benchmarks.verify_dleq += one_run.verify_dleq;
        total_benchmarks.token_size = one_run.token_size;
        total_benchmarks.total_client_generate += one_run.total_client_generate;
        one_run = ClientBenchmarks{};
    }

    void WebClient::get_and_redeem_tokens(int amount, int runs)
    {
        for (int i = 0; i < runs; i++)
        {
            get_tokens(amount);
            for (int i = 0; i < amount; i++)
            {
                redeem_token();
            }
            std::cout << "Benchmarks for run " << i << " with " << amount << " tokens:" << std::endl;
            print_benchmarks(amount, 1, one_run_benchmarks);
            add_benchmarks(total_benchmarks, one_run_benchmarks);
        }
        std::cout << "Benchmarks for Privacy Pass:" << std::endl;
        std::cout << "Amount of tokens: " << amount << " and averaged over " << runs << " execution runs " << std::endl;
        std::cout << std::endl;
        print_benchmarks(amount, runs, total_benchmarks);
    }

}