#pragma once
#include "crypto/ep_group/ep.h"
#include "crypto/privacy_pass/structs.h"
#include <iostream>
#include <span>

namespace DLEQ
{
    // X is a standardized generator for the configurated elliptic curve and P is a random element which was sampled beforehand.
    // Since we are working in a subgroup with prime order,
    // all points on the curve are generators.

    Proof Prove(const EpGroup::EP &Y, const EpGroup::EP &P, const EpGroup::EP &Q, const EpGroup::BN &k);

    std::vector<EpGroup::BN> sampleRandomElementsFromPRNG(const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q);

    BatchedElements calculateBatchedElements(const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q);

    Proof BatchProve(const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q, const EpGroup::BN &k);

    bool Verify(const Proof &proof, const EpGroup::EP &Y, const EpGroup::EP &P, const EpGroup::EP &Q);

    bool BatchVerify(const Proof &proof, const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q);

    void test_dleq();

}