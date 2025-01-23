#include "networking/GVRFClient.h"
#include "networking/beast/client.h"

#include "networking/certs/root_certificates.hpp"
#include "crypto/bilinear_group/deserializer.h"
#include "crypto/bilinear_group/serializer.h"
#include "crypto/bilinear_group/group.h"

namespace GVRF
{
    WebClient::WebClient(Config &conf, int *l) : ctx(ssl::context::tlsv13_client), client(l)
    {
        ctx.use_certificate_file("./cert/localhost.crt", boost::asio::ssl::context_base::file_format::pem);
        // ctx.set_verify_mode(ssl::verify_peer);
        //  load_root_certificates(ctx);
        ctx.set_verify_mode(ssl::verify_none);
        this->port = std::to_string(conf.port);
        this->address = conf.address.to_string();
        std::string target = "/GVRFGetPK";
        std::cout
            << "starting client connnecting to" << conf.address.to_string() << ":" << conf.port << std::endl;
        std::vector<uint8_t> buf;

        http::request<http::vector_body<uint8_t>> req = create_request(buf, target);

        auto const session = std::make_shared<NetworkingClient::session>(
            net::make_strand(ioc),
            ctx, req);

        session->run(address.c_str(), port.c_str());
        ioc.run();
        BilinearGroup::Deserializer des(session->res_.body());
        std::vector<BilinearGroup::G2> pk;
        des >> pk;
        client.add_pk_sig(pk);
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

    void WebClient::generate()
    {
        auto start = std::chrono::high_resolution_clock::now();
        int l = 2;
        auto start_kg = std::chrono::high_resolution_clock::now();

        client.KeyGen(&l);
        auto end_kg = std::chrono::high_resolution_clock::now();
        auto total_kg = end_kg - start_kg;
        std::string target_join = "/GVRFJoin";
        std::vector<uint8_t> pk_buf;
        BilinearGroup::Serializer ser(pk_buf);
        ser << client.get_public_key();
        ioc.reset();
        this->one_run_benchmarks.generate_req = pk_buf.size();
        http::request<http::vector_body<uint8_t>> req_join = create_request(pk_buf, target_join);

        auto const cert_session = std::make_shared<NetworkingClient::session>(
            net::make_strand(ioc),
            ctx, req_join);

        cert_session->run(address.c_str(), port.c_str());
        ioc.run();
        this->one_run_benchmarks.generate_res = cert_session->res_.body().size();
        BilinearGroup::Deserializer certificate_des(cert_session->res_.body());
        SPSEQ::Signature cert;
        certificate_des >> cert.Y;
        certificate_des >> cert.Y_hat;
        certificate_des >> cert.Z;
        auto start_ver_cert = std::chrono::high_resolution_clock::now();

        client.add_certificate(cert);
        auto end_ver_cert = std::chrono::high_resolution_clock::now();
        auto total_ver_cert = end_ver_cert - start_ver_cert;

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time = end - start;
        one_run_benchmarks.generate = elapsed_time;
        one_run_benchmarks.generate_client = total_ver_cert + total_kg;
    }

    void WebClient::expand(int &amount)
    {
        auto start_gen_token = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < amount; i++)
        {
            BilinearGroup::BN policy = BilinearGroup::BN(i);
            evals.push_back({client.Eval(policy), policy});
        };
        auto end_gen_token = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed_time_token_gen = end_gen_token - start_gen_token;
        one_run_benchmarks.expand = elapsed_time_token_gen;
    }

    void WebClient::verify()
    {
        if (evals.size() > 0)
        {
            auto start = std::chrono::high_resolution_clock::now();
            ioc.reset();

            std::string target = "/GVRFRedeem";

            auto it = evals.begin();
            Eval eval = *it;
            evals.erase(it);
            std::vector<uint8_t> buffer;
            BilinearGroup::Serializer ser(buffer);
            ser << eval.input;
            ser << eval.output.blinded_cert.cert_hat.Y;
            ser << eval.output.blinded_cert.cert_hat.Y_hat;
            ser << eval.output.blinded_cert.cert_hat.Z;
            ser << eval.output.blinded_cert.pi_prime;
            ser << eval.output.blinded_cert.pk_hat;
            ser << eval.output.y;
            this->one_run_benchmarks.token_size = buffer.size();
            http::request<http::vector_body<uint8_t>> req = create_request(buffer, target);
            auto const session = std::make_shared<NetworkingClient::session>(
                net::make_strand(ioc),
                ctx, req);
            // Request size is always the same. Somewhat unneccessary to assign the req size everytime
            one_run_benchmarks.redemption_request_size = req.body().size();
            session->run(address.c_str(), port.c_str());
            ioc.run();
            bool accepted = session->res_.body()[0];
            if (!accepted)
            {
                std::cout << "token was not successfully redeemed" << std::endl;
                exit(1);
            }
            auto end = std::chrono::high_resolution_clock::now();
            std::chrono::duration<double> elapsed_time = end - start;
            one_run_benchmarks.verify += elapsed_time;
        }
        else
        {
            std::cout << "there are no generated tokens to redeem" << std::endl;
        }
    }

    void add_benchmarks_to_total(ClientBenchmarks &total_benchmarks, ClientBenchmarks &one_run)
    {
        total_benchmarks.redemption_request_size = one_run.redemption_request_size;
        total_benchmarks.generate += one_run.generate;
        total_benchmarks.verify += one_run.verify;
        total_benchmarks.expand += one_run.expand;
        total_benchmarks.token_size = one_run.token_size;
        total_benchmarks.generate_res = one_run.generate_res;
        total_benchmarks.generate_req = one_run.generate_req;
        total_benchmarks.generate_client += one_run.generate_client;

        one_run = ClientBenchmarks{};
    }

    void print_benchmarks(int runs, int amount, ClientBenchmarks &benchmarks)
    {
        std::cout << "Average total time for Generate() ";
        std::cout << benchmarks.generate.count() / runs << " seconds" << std::endl;
        std::cout
            << "From that only client computation is: " << benchmarks.generate_client.count() / runs << "seconds" << std::endl;
        std::cout << std::endl;
        std::cout << "Average time for calling Expand() " << amount << " times: " << benchmarks.expand.count() / (runs) << " seconds" << std::endl;
        std::cout << "Average time for calling Expand() 1 time: " << benchmarks.expand.count() / (runs * amount) << " seconds" << std::endl;

        std::cout << "Average time for redeeming " << amount << " tokens is " << benchmarks.verify.count() / (runs) << " seconds" << std::endl;

        std::cout << "Average time for redeeming one token is: " << benchmarks.verify.count() / (runs * amount) << " seconds" << std::endl;
        std::cout << std::endl;
        std::cout << "Payload sizes of the HTTP packets in bytes:" << std::endl;
        std::cout << "Redemption Request (Client->Server): " << benchmarks.redemption_request_size << std::endl;
        std::cout << "Token size: " << benchmarks.token_size << std::endl;
        std::cout << "Generate Request (Client->Server): " << benchmarks.generate_req << std::endl;
        std::cout << "Generate Response (Client->Server): " << benchmarks.generate_res << std::endl;
    }

    void WebClient::get_and_redeem_tokens(int amount, int runs)
    {
        for (int i = 0; i < runs; i++)
        {
            generate();
            expand(amount);
            for (int i = 0; i < amount; i++)
            {
                verify();
            }
            print_benchmarks(1, amount, one_run_benchmarks);

            add_benchmarks_to_total(total_benchmarks, one_run_benchmarks);
            std::cout << "Benchmarks for run " << i << std::endl;
        };
        std::cout << "Finished Benchmarking for GVRF.." << std::endl;
        std::cout << "Amount of tokens: " << amount << " and averaged over " << runs << " execution runs " << std::endl;
        std::cout << std::endl;
        print_benchmarks(runs, amount, total_benchmarks);
    }
}