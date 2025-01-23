#include "networking/beast/server.h"
#include "crypto/privacy_pass/server.h"
#include "crypto/ep_group/deserializer.h"
#include "crypto/ep_group/serializer.h"
namespace PrivacyPass
{
    struct Benchmarks
    {
        std::chrono::duration<double> signing;
        std::chrono::duration<double> proof;
        std::chrono::duration<double> total_signing;
        std::chrono::duration<double> total_redeem_token;
    };
    class RequestHandler
    {
    public:
        RequestHandler(const std::string address, std::shared_ptr<Benchmarks> &benchmarks, std::shared_ptr<uint> &runs_sign, std::shared_ptr<uint> &runs_redeem) : server(), address(address), benchmarks(benchmarks), runs_redeem(runs_redeem), runs_sign(runs_sign) {};

        template <class Allocator>
        void create_response(http::request<http::vector_body<uint8_t>, http::basic_fields<Allocator>> &&req, http::response<http::vector_body<uint8_t>> *res)
        {

            std::string target = req.target().begin();
            EpGroup::Deserializer des(req.body());
            std::vector<uint8_t> buffer;
            EpGroup::Serializer ser(buffer);
            if (target == "/PPTokenSign")
            {
                std::vector<EpGroup::EP> tokens;
                des >> tokens;

                std::vector<EpGroup::EP> signed_tokens(tokens.size());
                auto start_sign = std::chrono::high_resolution_clock::now();

                for (int i = 0; i < tokens.size(); i++)
                {
                    signed_tokens[i] = server.Sign(tokens[i]);
                }
                auto end_sign = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> sign_time = end_sign - start_sign;
                benchmarks->signing += sign_time;

                DLEQ::Proof proof;
                auto start_proof_time = std::chrono::high_resolution_clock::now();

                if (tokens.size() > 1)
                {
                    proof = server.BatchProve(tokens, signed_tokens);
                }
                else
                {
                    proof = server.Prove(tokens[0], signed_tokens[0]);
                }
                auto end_proof_time = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> total_proof_time = end_proof_time - start_proof_time;
                benchmarks->proof += total_proof_time;
                benchmarks->total_signing += total_proof_time + sign_time;

                ser << proof.c;
                ser << proof.s;
                ser << signed_tokens;
                std::cout << "for run sign" << (*runs_sign) << ": " << std::endl;
                std::cout << "sign run time: " << (total_proof_time + sign_time).count() << " seconds " << std::endl;
                std::cout << "Average total time of AT.Generate(): ";
                std::cout << benchmarks->total_signing.count() / (*runs_sign) << " seconds" << std::endl;
                std::cout << "From that " << benchmarks->signing.count() / (*runs_sign) << " seconds for signing" << std::endl;
                std::cout << "and " << benchmarks->proof.count() / (*runs_sign) << " seconds for creating the DLEQ Proof" << std::endl;
                std::cout << std::endl;
                std::cout << "Average time for redeeming one token with AT.Verify()" << benchmarks->total_redeem_token.count() / (*runs_redeem) << " seconds" << std::endl;

                std::cout << std::endl;
                (*runs_sign)++;
            }
            else if (target == "/PPTokenRedeem")
            {
                std::vector<uint8_t> mac;
                des >> mac;
                EpGroup::BN t;
                des >> t;
                std::vector<uint8_t> R;
                auto start_redeem_time = std::chrono::high_resolution_clock::now();

                // Convert the string to uint8_t and insert into the vector
                for (char c : target)
                {
                    R.push_back(static_cast<uint8_t>(c));
                }
                size_t length = 0;

                for (char c : address)
                {
                    R.push_back(static_cast<uint8_t>(c));
                }
                ClientRedeem cr = {t, mac};
                bool verified = server.Redeem(cr, R);
                buffer.push_back(verified);
                auto end_redeem_time = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> redeem_time = end_redeem_time - start_redeem_time;
                benchmarks->total_redeem_token += redeem_time;
                std::cout << "for run redeem " << (*runs_redeem) << ": " << std::endl;
                std::cout << "redeem run: " << redeem_time.count() << " seconds" << std::endl;
                std::cout << "Average total time of AT.Generate(): ";
                std::cout << benchmarks->total_signing.count() / (*runs_sign) << " seconds" << std::endl;
                std::cout << "From that " << benchmarks->signing.count() / (*runs_sign) << " seconds for signing" << std::endl;
                std::cout << "and " << benchmarks->proof.count() / (*runs_sign) << " seconds for creating the DLEQ Proof" << std::endl;
                std::cout << std::endl;
                std::cout << "Average time for redeeming one token with AT.Verify()" << benchmarks->total_redeem_token.count() / (*runs_redeem) << " seconds" << std::endl;

                std::cout << std::endl;
                (*runs_redeem)++;
            }
            else if (target == "/GetCommitedSK")
            {
                ser << server.get_c_sk();
            }
            else
            {
                std::cout << "Resource unknown to the server: " << target << std::endl;
                exit(1);
            };
            std::string path = "application/text";
            http::response<http::vector_body<uint8_t>> res_struct = {
                std::piecewise_construct,
                std::make_tuple(std::move(buffer)),
                std::make_tuple(http::status::ok, req.version())};
            *res = res_struct;
            auto const size = buffer.size();
            res->set(http::field::server, BOOST_BEAST_VERSION_STRING);
            res->set(http::field::content_type, mime_type(path));
            res->content_length(size);
            res->keep_alive(req.keep_alive());
            res->prepare_payload();
        }

    private:
        std::shared_ptr<Benchmarks> benchmarks;
        std::shared_ptr<uint> runs_sign;
        std::shared_ptr<uint> runs_redeem;
        Server server;
        const std::string address;
    };

    class Session : public session
    {
        std::shared_ptr<RequestHandler const> req_handler;

    public:
        Session(tcp::socket socket,
                ssl::context &ctx, std::shared_ptr<RequestHandler const> const &req_handler) : session(std::move(socket), ctx), req_handler(req_handler) {};
        void on_read(
            beast::error_code ec,
            std::size_t bytes_transferred) override
        {
            boost::ignore_unused(bytes_transferred);

            // This means they closed the connection
            if (ec == http::error::end_of_stream)
                return do_close();

            if (ec)
                return fail(ec, "read");

            // Send the response
            handle_request(*req_handler, std::move(req_), lambda_);
        }
    };

    class Listener : public listener
    {
        std::shared_ptr<RequestHandler const> req_handler;

    public:
        Listener(
            net::io_context &ioc,
            ssl::context &ctx,
            tcp::endpoint endpoint, std::shared_ptr<RequestHandler> const &req_handler)
            : listener(ioc, ctx, endpoint), req_handler(req_handler) {};

    private:
        void on_accept(beast::error_code ec, tcp::socket socket) override
        {
            if (ec)
            {
                fail(ec, "accept");
                return; // To avoid infinite loop
            }
            else
            {
                // Create the session and run it
                std::make_shared<Session>(
                    std::move(socket),
                    ctx_, req_handler)
                    ->run();
            }

            // Accept another connection
            do_accept();
        }
    };

    int start_server(Config &conf)
    {
        // The io_context is required for all I/O
        net::io_context ioc{conf.threads};

        // The SSL context is required, and holds certificates
        // ssl::context ctx{ssl::context::tlsv13};
        // load_server_certificate(ctx);
        ssl::context ctx{ssl::context::tlsv13_server};
        ctx.use_certificate_file("./cert/localhost.crt", boost::asio::ssl::context_base::file_format::pem);
        ctx.use_private_key_file("./cert/localhost.key", boost::asio::ssl::context_base::file_format::pem);
        std::cout
            << "server listening on " << conf.address.to_string() << ":" << conf.port << std::endl;

        // This holds the self-signed certificate used by the server
        // Create and launch a listening port
        auto benchmarks = std::make_shared<Benchmarks>();
        auto runs_sign = std::make_shared<uint>(1);
        auto runs_redeem = std::make_shared<uint>(1);

        auto const req_handler = std::make_shared<RequestHandler>(conf.address.to_string(), benchmarks, runs_sign, runs_redeem);
        std::make_shared<Listener>(
            ioc,
            ctx,
            tcp::endpoint{conf.address, conf.port}, req_handler)
            ->run();

        // Run the I/O service on the requested number of threads
        std::vector<std::thread> v;
        v.reserve(conf.threads - 1);
        for (auto i = conf.threads - 1; i > 0; --i)
            v.emplace_back(
                [&ioc]
                {
                    ioc.run();
                });
        ioc.run();

        return EXIT_SUCCESS;
    };

}