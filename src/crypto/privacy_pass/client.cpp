#include "crypto/privacy_pass/client.h"
namespace PrivacyPass
{
    Token Client::GetAndBlindToken()
    {
        EpGroup::BN t = EpGroup::BN::rand();
        EpGroup::EP T = GenToken(t);
        BlindedToken bt = BlindToken(T);
        return {bt, t};
    }
    
    EpGroup::EP Client::GenToken(EpGroup::BN &t)
    {

        int capacity = t.size();
        uint8_t *buffer = new uint8_t[capacity];
        t.serialize(buffer, capacity);
        EpGroup::EP T = EpGroup::EP::hash_to_group(buffer, capacity);
        delete[] buffer;
        return T;
    }

    BlindedToken Client::BlindToken(EpGroup::EP &T)
    {
        EpGroup::BN r = EpGroup::BN::rand();
        return {T * r, r};
    }

    EpGroup::EP Client::Unblind(EpGroup::EP &T_hat, EpGroup::BN &r)
    {
        EpGroup::BN r_inv;
        EpGroup::BN::mod_inverse(r_inv, r, EpGroup::BN::get_group_order());
        return T_hat * r_inv;
    }

    ClientRedeem Client::Redeem(std::vector<uint8_t> &R)
    {
        if (tokens.size() > 0)
        {
            auto it = tokens.begin();
            ClientToken removedToken = *it;
            tokens.erase(it);
            std::vector<uint8_t> K = sKGen(removedToken.t, removedToken.T);
            std::vector<uint8_t> s = EpGroup::hmac(K, R);
            return {removedToken.t, s};
        }
        else
        {
            std::cout << "there is currently no token stored to redeem" << std::endl;
            exit(1);
        }
    }

    std::vector<uint8_t> Client::sKGen(EpGroup::BN &t, EpGroup::EP &B)
    {
        int buffer_size = t.size() + B.buffer_size();
        uint8_t *buffer = new uint8_t[buffer_size];
        uint8_t *buffer_t = new uint8_t[t.size()];
        t.serialize(buffer_t, t.size());
        uint8_t *buffer_B = new uint8_t[B.buffer_size()];
        B.serialize(buffer_B, B.buffer_size());
        std::copy(buffer_t, buffer_t + t.size(), buffer);
        std::copy(buffer_B, buffer_B + B.buffer_size(), buffer + t.size());
        std::vector<uint8_t> key =
            EpGroup::hash(buffer, buffer_size);
        delete[] buffer_t;
        delete[] buffer_B;
        delete[] buffer;
        return key;
    }
}