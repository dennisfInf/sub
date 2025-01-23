#include "crypto/gvrfs/server.h"
#include "crypto/gvrfs/client.h"
namespace GVRF
{
    SPSEQ::Signature Server::Join(std::vector<BilinearGroup::G1> &pk)
    {
        if (pk.size() < l)
        {
            std::cout << "size of pk is not equal to l in Server::Join" << std::endl;
            exit(1);
        }
        return sps_eq.Sign(pk);
    };

    bool Server::Ver(BilinearGroup::BN &x, BilinearGroup::GT &y, BlindedCertficicate &pi)
    {
        // Verifies the blinded certificate, if the server actually signed the referenced public key
        std::future<bool> verify_cert = BilinearGroup::pool.push(
            [this, &pk_hat = pi.pk_hat, &cert_hat = pi.cert_hat](int)
            {
                return sps_eq.Verify(pk_hat, cert_hat);
            });

        // pk_hat[0] is equal to pk^_1 and pk_hat[1] is equal to pk^_2.
        //
        std::future<BilinearGroup::GT> left_eq_1 = BilinearGroup::pool.push(
            [&pk1_hat = pi.pk_hat[0], &x, &pk2_hat = pi.pk_hat[1], &pi_prime = pi.pi_prime](int)
            {
                return BilinearGroup::GT::map((pk1_hat * x) + pk2_hat, pi_prime);
            });

        std::future<BilinearGroup::GT> left_eq_2 = BilinearGroup::pool.push(
            [&pk1_hat = pi.pk_hat[0], &pi_prime = pi.pi_prime](int)
            {
                return BilinearGroup::GT::map(pk1_hat, pi_prime);
            });

        std::future<bool> verify_eq_1 = BilinearGroup::pool.push(
            [&left_eq_1](int)
            {
                // Avoids the pairing operation to get the generator of GT, since RELIC provides an interface to get it.
                BilinearGroup::GT right_eq_1 = BilinearGroup::GT::get_gen();
                return left_eq_1.get() == right_eq_1;
            });

        std::future<bool> verify_eq_2 = BilinearGroup::pool.push(
            [&left_eq_2, &y](int)
            {
                return left_eq_2.get() == y;
            });

        // Waits for all threads to finish
        if (verify_cert.get() && verify_eq_1.get() && verify_eq_2.get())
        {
            return true;
        }
        else
        {
            std::cout << "verification of the gvrf evaluation failed" << std::endl;
        };
    }
    bool Server::Judge(std::vector<BilinearGroup::G1> &pk, BilinearGroup::BN &x, FOutput &eval)
    {
        std::future<BilinearGroup::G1> left_eq_1 = BilinearGroup::pool.push(
            [&pk = pk[0], &tau = eval.tau](int)
            {
                return pk * tau;
            });

        std::future<BilinearGroup::G1> left_eq_2 = BilinearGroup::pool.push(
            [&pk = pk[1], &tau = eval.tau](int)
            {
                return pk * tau;
            });

        std::future<bool> verify_eq_1 = BilinearGroup::pool.push(
            [&blinded_pk = eval.blinded_cert.pk_hat[0], &left_eq_1](int)
            {
                return blinded_pk == left_eq_1.get();
            });

        std::future<bool> verify_eq_2 = BilinearGroup::pool.push(
            [&blinded_pk = eval.blinded_cert.pk_hat[1], &left_eq_2](int)
            {
                return blinded_pk == left_eq_2.get();
            });

        std::future<bool> verify_eq_3 = BilinearGroup::pool.push(
            [this, &blinded_cert = eval.blinded_cert, &x, &y = eval.y](int)
            {
                return Ver(x, y, blinded_cert);
            });

        if (verify_eq_1.get() && verify_eq_2.get() && verify_eq_3.get())
        {
            return true;
        }
        else
        {
            std::cout << "Verification in Server::Judge failed" << std::endl;
            exit(1);
        }
    }

    void test_gvrf(int l)
    {
        // Create client and server objects. The constructor generates their keys already.
        Server server(&l);
        std::vector<BilinearGroup::G2> server_pk = server.get_public_key();

        Client client(&l, server_pk);
        // get the generated public key of the client
        std::vector<BilinearGroup::G1> client_pk = client.get_public_key();
        // Input it to the server to get the certificate
        SPSEQ::Signature client_cert = server.Join(client_pk);
        // add the resulting certificate to the client class, but verify it beforehand
        assert(client.add_certificate(client_cert));
        std::cout << "Client certificate verified.." << std::endl;
        // Sample random X
        BilinearGroup::BN x = BilinearGroup::BN::rand();
        // Evaluate x
        FOutput eval = client.Eval(x);
        // Verify output of gvrf
        assert(server.Ver(x, eval.y, eval.blinded_cert));
        std::cout << "GVRF Ver test passed" << std::endl;
        assert(server.Judge(client_pk, x, eval));
        std::cout << "GVRF Judge test passed" << std::endl;
    };

}