#pragma once
#include "crypto/ep_group/ep.h"
#include "crypto/privacy_pass/structs.h"
#include "crypto/privacy_pass/nizk.h"
namespace PrivacyPass
{
    class Server
    {
    public:
        Server() : sk(EpGroup::BN::rand()) { c_sk = EpGroup::EP::get_gen() * sk; };
        EpGroup::EP Sign(EpGroup::EP &T_hat);
        EpGroup::EP Commit();
        DLEQ::Proof Prove(EpGroup::EP &P, EpGroup::EP &Q)
        {
            return DLEQ::Prove(c_sk, P, Q, sk);
        };

        DLEQ::Proof BatchProve(std::vector<EpGroup::EP> &P, std::vector<EpGroup::EP> &Q)
        {
            return DLEQ::BatchProve(c_sk, P, Q, sk);
        };
        EpGroup::EP get_c_sk()
        {
            return c_sk;
        }
        bool Redeem(ClientRedeem &cr, std::vector<uint8_t> &R);

    private:
        EpGroup::BN sk;
        EpGroup::EP c_sk;
        std::vector<EpGroup::BN> ts;
    };

    void test_privacy_pass();
};