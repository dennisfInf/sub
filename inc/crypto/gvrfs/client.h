#pragma once
#include "crypto/bilinear_group/group.h"
#include "crypto/gvrfs/structs.h"
namespace GVRF
{

    class Client
    {
    public:
        Client(int *l, std::vector<BilinearGroup::G2> &pk_sig) : key(KeyGen(l)), l(*l), pk_sig(pk_sig){};
        Client(int *l) : key(KeyGen(l)), l(*l){};
        FOutput Eval(BilinearGroup::BN &x);
        bool add_certificate(SPSEQ::Signature &cert);
        std::vector<BilinearGroup::G1> get_public_key() { return key.pk; };
        void add_pk_sig(std::vector<BilinearGroup::G2> &pk_sig)
        {
            this->pk_sig = pk_sig;
        }
        Key KeyGen(int *l);

    private:
        bool VerCert(SPSEQ::Signature &_cert);
        Key key;
        int l;
        std::vector<BilinearGroup::G2> pk_sig;
        SPSEQ::Signature cert;
    };
}