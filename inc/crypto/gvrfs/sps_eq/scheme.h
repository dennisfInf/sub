#pragma once
#include "group.h"
#include "cassert"
#include <iostream>
namespace SPSEQ
{
    struct Key
    {
        std::vector<BilinearGroup::BN> sk;
        std::vector<BilinearGroup::G2> pk;
    };

    struct Signature
    {
        BilinearGroup::G1 Z;
        BilinearGroup::G1 Y;
        BilinearGroup::G2 Y_hat;
    };

    class Scheme
    {
    public:
        Scheme(int *l) : l(l), key(KeyGen(l)){};
        Signature Sign(std::vector<BilinearGroup::G1> &M);
        static bool Verify(std::vector<BilinearGroup::G1> &M, Signature &sig, std::vector<BilinearGroup::G2> &pk);
        static Signature ChgRep(std::vector<BilinearGroup::G1> &M, Signature &sig, BilinearGroup::BN &my, std::vector<BilinearGroup::G2> &pk);
        bool VKey();
        bool Verify(std::vector<BilinearGroup::G1> &M, Signature &sig)
        {
            return Scheme::Verify(M, sig, this->key.pk);
        };
        Signature ChgRep(std::vector<BilinearGroup::G1> &M, Signature &sig, BilinearGroup::BN &my)
        {
            return Scheme::ChgRep(M, sig, my, this->key.pk);
        };
        static std::vector<BilinearGroup::G1> blind_message(BilinearGroup::BN &my, std::vector<BilinearGroup::G1> &M);
        std::vector<BilinearGroup::G2> get_public_key()
        {
            return key.pk;
        };

    private:
        Key KeyGen(int *l);
        int *l;
        Key key;
    };

    void test(int l);
};