// Bilinear groups are not used here.
#pragma once
#include "crypto/ep_group/ep.h"
#include "crypto/privacy_pass/structs.h"
#include "crypto/privacy_pass/nizk.h"
namespace PrivacyPass
{
    class Client
    {
    public:
        Client(){};
        Token GetAndBlindToken();
        bool Verify(DLEQ::Proof &proof, EpGroup::EP &Y, EpGroup::EP &P, EpGroup::EP &Q)
        {
            return DLEQ::Verify(proof, Y, P, Q);
        };
        bool BatchVerify(DLEQ::Proof &proof, EpGroup::EP &Y, std::vector<EpGroup::EP> &P, std::vector<EpGroup::EP> &Q)
        {
            return DLEQ::BatchVerify(proof, Y, P, Q);
        }
        EpGroup::EP Unblind(EpGroup::EP &T_hat, EpGroup::BN &r);
        void AddToken(ClientToken token)
        {
            tokens.push_back(token);
        }

        static EpGroup::EP GenToken(EpGroup::BN &t);
        static std::vector<uint8_t> sKGen(EpGroup::BN &t, EpGroup::EP &B);
        ClientRedeem Redeem(std::vector<uint8_t> &R);

    private:
        BlindedToken BlindToken(EpGroup::EP &T);
        std::vector<ClientToken> tokens;
    };
}