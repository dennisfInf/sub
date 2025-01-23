#pragma once
#include "crypto/gvrfs/structs.h"
namespace GVRF
{
    class Server
    {
    public:
        Server(int *l) : sps_eq(l), l(*l){};
        SPSEQ::Signature Join(std::vector<BilinearGroup::G1> &pk);
        bool Ver(BilinearGroup::BN &x, BilinearGroup::GT &y, BlindedCertficicate &pi);
        bool Judge(std::vector<BilinearGroup::G1> &pk, BilinearGroup::BN &x, FOutput &eval);
        std::vector<BilinearGroup::G2> get_public_key() { return sps_eq.get_public_key(); };

    private:
        SPSEQ::Scheme sps_eq;
        int l;
    };

    void test_gvrf(int l);
};