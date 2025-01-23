#include "crypto/gvrfs/client.h"
namespace GVRF
{
    // Ignoring the l parameter. GVRFS sets l=2. Parameter is not removed for potential adjustments later on.
    Key Client::KeyGen(int *)
    {
        // Samples random element from Z_p
        BilinearGroup::BN sk = BilinearGroup::BN::rand();
        // Initializes the key consisting of a sk and pk=(pk_1,pk_2)
        std::vector<BilinearGroup::G1> pk(2);
        BilinearGroup::G1 g1 = BilinearGroup::G1::get_gen();
        pk[0] = g1;
        pk[1] = g1 * sk;

        return {sk, pk};
    };

    FOutput Client::Eval(BilinearGroup::BN &x)
    {
        // Generator of G2
        BilinearGroup::G2 g2 = BilinearGroup::G2::get_gen();
        // Samples random element from Z_p
        std::future<BilinearGroup::BN> tau_fut = BilinearGroup::pool.push(
            [](int)
            {
                return BilinearGroup::BN::rand();
            });
        // 1/(x+sk)
        BilinearGroup::BN x_add_sk = x + key.sk;
        // Calculates the mod inverse of (x+sk). BN group order is equivalent to the order of G1. Stores the result in x_add_sk_inv.
        BilinearGroup::BN x_add_sk_inv;
        BilinearGroup::BN::mod_inverse(x_add_sk_inv, x_add_sk, BilinearGroup::BN::get_group_order());
        // Calculates e(g_1,g_2)^(1/(x+sk)). Additive notation is used in the code.
        BilinearGroup::GT y = BilinearGroup::GT::map(BilinearGroup::G1::get_gen(), g2) * x_add_sk_inv;
        // Calculates g_2^(1/(tau(x+sk)))
        BilinearGroup::BN tau_times_x_add_sk_inv;
        BilinearGroup::BN tau = tau_fut.get();
        BilinearGroup::BN::mod_inverse(tau_times_x_add_sk_inv, tau * x_add_sk, BilinearGroup::BN::get_group_order());
        BilinearGroup::G2 pi_prime = g2 * tau_times_x_add_sk_inv;
        std::future<std::vector<BilinearGroup::G1>> blind_msg_fut = BilinearGroup::pool.push(
            [&tau, &key = this->key.pk](int)
            {
                return SPSEQ::Scheme::blind_message(tau, key);
            });

        std::future<SPSEQ::Signature> blind_cert_fut = BilinearGroup::pool.push(
            [&tau, &key = this->key.pk, &cert = this->cert, &pk_sig = this->pk_sig](int)
            {
                return SPSEQ::Scheme::ChgRep(key, cert, tau, pk_sig);
            });

        // Blinds the public key of the user (message) and blinds the corresponding signature in the certificate with the same tau
        return {
            y, {pi_prime, blind_msg_fut.get(), blind_cert_fut.get()}, tau};
    };

    // This is simply the VerCert method in the paper. Additionally it adds the certificate to the class of the client, if it is verified successfully.
    bool Client::add_certificate(SPSEQ::Signature &cert)
    {
        if (VerCert(cert))
        {
            this->cert = cert;
            return true;
        }
        else
        {
            return false;
        }
    }

    bool Client::VerCert(SPSEQ::Signature &cert)
    {
        // Verifies if the pk of the client is correctly signed by the server using the servers public key referenced in the certificate (cert.pk_sig)
        return SPSEQ::Scheme::Verify(key.pk, cert, pk_sig);
    }
}