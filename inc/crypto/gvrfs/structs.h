#pragma once
#include "crypto/gvrfs/sps_eq/scheme.h"

namespace GVRF
{
    struct Key
    {
        BilinearGroup::BN sk;
        std::vector<BilinearGroup::G1> pk;
    };

    struct BlindedCertficicate
    {
        BilinearGroup::G2 pi_prime;
        std::vector<BilinearGroup::G1> pk_hat;
        SPSEQ::Signature cert_hat;
    };

    struct FOutput
    {
        BilinearGroup::GT y;
        BlindedCertficicate blinded_cert;
        BilinearGroup::BN tau;
    };

    struct Eval
    {
        FOutput output;
        BilinearGroup::BN input;
    };
}