#include "crypto/privacy_pass/server.h"
#include "crypto/privacy_pass/client.h"
#include "crypto/privacy_pass/nizk.h"
#include "crypto/privacy_pass/structs.h"
#include <cassert>
namespace PrivacyPass
{
    EpGroup::EP Server::Sign(EpGroup::EP &T_hat)
    {
        return T_hat * sk;
    }

    EpGroup::EP Server::Commit()
    {
        return EpGroup::EP::get_gen() * sk;
    }

    bool Server::Redeem(ClientRedeem &cr, std::vector<uint8_t> &R)
    {
        for (auto &t : ts)
        {
            if (t == cr.t)
            {
                return false;
            }
        }
        EpGroup::EP token = Client::GenToken(cr.t);
        EpGroup::EP signed_t = Sign(token);
        std::vector<uint8_t>
            K = Client::sKGen(cr.t, signed_t);
        std::vector<uint8_t> mac = EpGroup::hmac(K, R);
        if (cr.mac == mac)
        {
            ts.push_back(cr.t);
            return true;
        }
        return false;
    }

    void test_privacy_pass()
    {
        Client client = Client();
        Server server = Server();
        // Token Signing
        Token token = client.GetAndBlindToken();
        EpGroup::EP f_sk_of_T_hat = server.Sign(token.bt.T_hat);
        DLEQ::Proof proof = server.Prove(token.bt.T_hat, f_sk_of_T_hat);
        EpGroup::EP c_sk = server.get_c_sk();
        assert(client.Verify(proof, c_sk, token.bt.T_hat, f_sk_of_T_hat));
        std::cout << "DLEQ verified in privacy pass" << std::endl;
        client.AddToken({token.t, client.Unblind(f_sk_of_T_hat, token.bt.r)});
        // Token Redemption
        // Hard-coded R, enough for testing
        std::vector<uint8_t> R = {125, 125, 125, 125, 125, 125, 125, 125, 125, 125};
        ClientRedeem cr = client.Redeem(R);
        assert(server.Redeem(cr, R));
        std::cout << "token redemption was successfull" << std::endl;
        // Generate 50 Tokens at once and Redeem them
        std::cout << "testing batch signing" << std::endl;
        int amount = 50;
        std::vector<Token> tokens(amount);
        std::vector<EpGroup::EP> P_s(amount);
        std::vector<EpGroup::EP> signed_tokens(amount);
        for (int i = 0; i < amount; i++)
        {
            tokens[i] = client.GetAndBlindToken();
            P_s[i] = tokens[i].bt.T_hat;
            signed_tokens[i] = server.Sign(P_s[i]);
        }
        DLEQ::Proof batch_proof = server.BatchProve(P_s, signed_tokens);
        assert(client.BatchVerify(batch_proof, c_sk, P_s, signed_tokens));
        std::cout << "batch verification of " << amount << " tokens was successfull" << std::endl;
        for (int i = 0; i < amount; i++)
        {
            client.AddToken({tokens[i].t, client.Unblind(signed_tokens[i], tokens[i].bt.r)});
        }
        for (int i = 0; i < amount; i++)
        {
            ClientRedeem cr = client.Redeem(R);
            assert(server.Redeem(cr, R));
        }
        std::cout << "all " << amount << " redemptions were successfull" << std::endl;
    }
}