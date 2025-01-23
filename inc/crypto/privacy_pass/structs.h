#pragma once
#include "crypto/ep_group/ep.h"
namespace PrivacyPass
{
    
    struct BlindedToken
    {
        EpGroup::EP T_hat;
        EpGroup::BN r;
    };

    struct Token
    {
        BlindedToken bt;
        EpGroup::BN t;
    };

    struct ClientToken
    {
        EpGroup::BN t;
        EpGroup::EP T;
    };

    struct ClientRedeem
    {
        EpGroup::BN t;
        std::vector<uint8_t> mac;
    };
}

namespace DLEQ
{
    struct BatchedElements
    {
        EpGroup::EP M;
        EpGroup::EP Z;
    };
    struct Proof
    {
        EpGroup::BN c;
        EpGroup::BN s;
    };
}