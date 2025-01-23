#include "networking/beast/server.h"
#include "crypto/gvrfs/server.h"
#include "crypto/bilinear_group/deserializer.h"
#include "crypto/bilinear_group/serializer.h"

namespace GVRF
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
        RequestHandler(const std::string address, int *l, std::shared_ptr<Benchmarks> &benchmarks, std::shared_ptr<uint> &runs_redeem, std::shared_ptr<uint> &runs_join) : server(l), address(address), benchmarks(benchmarks), runs_redeem(runs_redeem), runs_join(runs_join) {};

        template <class Allocator>
        void create_response(http::request<http::vector_body<uint8_t>, http::basic_fields<Allocator>> &&req, http::response<http::vector_body<uint8_t>> *res)
        {
            std::string target = req.target().begin();
            BilinearGroup::Deserializer des(req.body());
            std::vector<uint8_t> buffer;
            BilinearGroup::Serializer ser(buffer);

            if (target == "/GVRFRedeem")
            {
                BilinearGroup::BN x;
                BilinearGroup::GT y;
                BlindedCertficicate blinded_cert;
                des >> x;
                des >> blinded_cert.cert_hat.Y;
                des >> blinded_cert.cert_hat.Y_hat;
                des >> blinded_cert.cert_hat.Z;
                des >> blinded_cert.pi_prime;
                des >> blinded_cert.pk_hat;
                des >> y;
                auto start_redeem = std::chrono::high_resolution_clock::now();

                bool verified = server.Ver(x, y, blinded_cert);
                auto end_redeem = std::chrono::high_resolution_clock::now();
                auto total_redeem = end_redeem - start_redeem;
                benchmarks->total_redeem_token += total_redeem;
                std::cout << "for run redeem" << (*runs_redeem) << ": " << std::endl;
                std::cout << "Average total time of AT.Generate(): ";
                std::cout << benchmarks->total_signing.count() / (*runs_join) << " seconds" << std::endl;
                std::cout << std::endl;
                std::cout << "Average time for redeeming one token with AT.Verify()" << benchmarks->total_redeem_token.count() / (*runs_redeem) << " seconds" << std::endl;
                (*runs_redeem)++;
                std::cout << std::endl;
                buffer.push_back(verified);
            }
            else if (target == "/GVRFJoin")
            {
                std::vector<BilinearGroup::G1> client_pk;
                des >> client_pk;
                auto start_join = std::chrono::high_resolution_clock::now();

                SPSEQ::Signature cert = server.Join(client_pk);
                auto end_join = std::chrono::high_resolution_clock::now();
                auto total_join = end_join - start_join;
                benchmarks->total_signing += total_join;
                std::cout << "for run join" << (*runs_join) << ": " << std::endl;
                std::cout << "Average total time of AT.Generate(): ";
                std::cout << benchmarks->total_signing.count() / (*runs_join) << " seconds" << std::endl;
                std::cout << std::endl;
                std::cout << "Average time for redeeming one token with AT.Verify()" << benchmarks->total_redeem_token.count() / (*runs_redeem) << " seconds" << std::endl;
                (*runs_join)++;
                std::cout << std::endl;
                ser << cert.Y;
                ser << cert.Y_hat;
                ser << cert.Z;
            }
            else if (target == "/GVRFGetPK")
            {
                ser << server.get_public_key();
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
        std::shared_ptr<uint> runs_redeem;
        std::shared_ptr<uint> runs_join;

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
        ssl::context ctx{ssl::context::tlsv13_server};
        ctx.use_certificate_file("./cert/localhost.crt", boost::asio::ssl::context_base::file_format::pem);
        ctx.use_private_key_file("./cert/localhost.key", boost::asio::ssl::context_base::file_format::pem);
        // ssl::context ctx{ssl::context::tlsv13};
        // load_server_certificate(ctx);
        std::cout
            << "server listening on " << conf.address.to_string() << ":" << conf.port << std::endl;

        // This holds the self-signed certificate used by the server
        // Create and launch a listening port
        int l = 2;
        auto benchmarks = std::make_shared<Benchmarks>();
        auto runs_redeem = std::make_shared<uint>(1);
        auto runs_join = std::make_shared<uint>(1);

        auto const req_handler = std::make_shared<RequestHandler>(conf.address.to_string(), &l, benchmarks, runs_redeem, runs_join);
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