#include "crypto/gvrfs/sps_eq/scheme.h"
#include <iostream>
namespace SPSEQ
{
    // Additive notation is used throughout this code.
    Key Scheme::KeyGen(int *l)
    {
        std::vector<BilinearGroup::BN> sk(*l); // Creates a vector of random Z_p elements, which is the sk
        std::generate(sk.begin(), sk.end(), []()
                      { return BilinearGroup::BN::rand(); });
        std::vector<BilinearGroup::G2> pk(*l); // Creates a vector of random Z_p elements, which is the sk
        pk.reserve(*l);
        BilinearGroup::G2 g2 = BilinearGroup::G2::get_gen();
        for (int i = 0; i < *l; i++)
        {
            pk[i] = g2 * sk[i];
        };
        return {sk, pk};
    };
    // Group elements are not verified here in Sign and Verify. This is done outside of this class, upon receiving data over the network.
    Signature Scheme::Sign(std::vector<BilinearGroup::G1> &M)
    {

        // Calculates Z = y * sum (x_i*M_i) in a seperate thread
        std::future<BilinearGroup::G1> fut_Z = BilinearGroup::pool.push(
            [this, &M](int)
            { 
        BilinearGroup::G1 Z = BilinearGroup::G1::get_infty();
        for (int i = 0; i < *l; i++)
        {
            Z += (this->key.sk[i] * M[i]);
        }; 
        return Z; });

        // sample random y from Z_p
        BilinearGroup::BN y = BilinearGroup::BN::rand();
        // calculates the multiplicative inverse of y in a seperate thread
        std::future<BilinearGroup::BN> fut_y_inv = BilinearGroup::pool.push(
            [this, &y](int)
            {
                BilinearGroup::BN y_inv;
                BilinearGroup::BN::mod_inverse(y_inv, y, BilinearGroup::BN::get_group_order());
                return y_inv;
            });

        // waits for Z = y * sum (x_i*M_i) to finish, then multiplies y to Z.
        std::future<BilinearGroup::G1> fut_Z2 = BilinearGroup::pool.push(
            [this, &fut_Z, &y](int)
            {
                BilinearGroup::G1 Z = fut_Z.get();
                return Z * y;
            });

        // waits for the inverse of y to finish calculating
        BilinearGroup::BN y_inv = fut_y_inv.get();

        // Spawns two threads, where the inverse of y is multiplied by the generator of the appropriate group
        std::future<BilinearGroup::G1> fut_Y = BilinearGroup::pool.push(
            [this, &y_inv](int)
            {
                return y_inv * BilinearGroup::G1::get_gen();
            });

        std::future<BilinearGroup::G2> fut_Y2 = BilinearGroup::pool.push(
            [this, &y_inv](int)
            {
                return y_inv * BilinearGroup::G2::get_gen();
            });

        // returns the signature. (Z,Y,Ŷ), where the inverse of y is multiplicated with the generator of the group respectively.
        return {fut_Z2.get(), fut_Y.get(), fut_Y2.get()};
    }

    // No Error handling. Program crashes if verification fails, thus one can verify, if no crashes occur, all signatures were verified successfully.
    bool Scheme::Verify(std::vector<BilinearGroup::G1> &M, Signature &sig, std::vector<BilinearGroup::G2> &pk)
    {
        std::vector<std::future<BilinearGroup::GT>> futures_left_eq_1;
        for (int i = 0; i < M.size(); i++)
        {
            futures_left_eq_1.push_back(BilinearGroup::pool.push(
                [&m = M[i], &pk = pk[i]](int)
                {
                    return BilinearGroup::GT::map(m, pk);
                }));
        };

        std::future<BilinearGroup::GT> future_right_eq_1 = BilinearGroup::pool.push(
            [&sig](int)
            {
                return BilinearGroup::GT::map(sig.Z, sig.Y_hat);
            });

        std::future<BilinearGroup::GT> future_left_eq_2 = BilinearGroup::pool.push(
            [&sig](int)
            {
                return BilinearGroup::GT::map(sig.Y, BilinearGroup::G2::get_gen());
            });

        std::future<BilinearGroup::GT> future_right_eq_2 = BilinearGroup::pool.push(
            [&sig](int)
            {
                return BilinearGroup::GT::map(BilinearGroup::G1::get_gen(), sig.Y_hat);
            });

        std::future<bool> verify_eq_1 = BilinearGroup::pool.push(
            [&futures_left_eq_1, &future_right_eq_1](int)
            {
                BilinearGroup::GT left_eq_1 = futures_left_eq_1[0].get();
                for (int i = 1; i < futures_left_eq_1.size(); i++)
                {
                    left_eq_1 += futures_left_eq_1[i].get();
                }
                return left_eq_1 == future_right_eq_1.get();
            });

        std::future<bool> verify_eq_2 = BilinearGroup::pool.push(
            [&future_left_eq_2, &future_right_eq_2](int)
            {
                return future_left_eq_2.get() == future_right_eq_2.get();
            });

        // Nested if statements are used here to actually know, which side of the equation failed for better traceability. This costs some readability.
        // eq 1: Prod of e(M_i,X^_i)=e(Z,Ŷ) , where Prod of e(M_i,X^_i) is left_eq_1
        if (verify_eq_1.get())
        {
            // pairing with the respective generators. eq 2: e(Y,P^)=e(P,Ŷ)
            if (verify_eq_2.get())
            {
                return true;
            }
            else
            {
                std::cout << "Verification of the message in SPS-EQ failed: EQ 2 does not hold" << std::endl;
                std::exit(1);
            }
        }
        else
        {
            std::cout << "Verification of the message in SPS-EQ failed: EQ 1 does not hold" << std::endl;
            std::exit(1);
        }
    }

    Signature Scheme::ChgRep(std::vector<BilinearGroup::G1> &M, Signature &sig, BilinearGroup::BN &my, std::vector<BilinearGroup::G2> &pk)
    {
        // Verifies the signature first
        if (Scheme::Verify(M, sig, pk))
        {
            // then blinds it occording to the scheme
            // samples psi
            BilinearGroup::BN psi = BilinearGroup::BN::rand();
            std::future<BilinearGroup::G1> fut_Z = BilinearGroup::pool.push(
                [&psi, &my, &Z = sig.Z](int)
                {
                    return psi * my * Z;
                });
            // multiplicative inverse of psi
            BilinearGroup::BN psi_inv;
            BilinearGroup::BN::mod_inverse(psi_inv, psi, BilinearGroup::BN::get_group_order());
            std::future<BilinearGroup::G1> fut_Y = BilinearGroup::pool.push(
                [&psi_inv, &Y = sig.Y](int)
                {
                    return psi_inv * Y;
                });

            std::future<BilinearGroup::G2> fut_Y2 = BilinearGroup::pool.push(
                [&psi_inv, &Y_hat = sig.Y_hat](int)
                {
                    return psi_inv * Y_hat;
                });

            return {fut_Z.get(), fut_Y.get(), fut_Y2.get()};
        }
        else
        {
            std::cout << "ChgRep failed, because the signature is invalid";
            std::exit(1);
        }
    }
    bool Scheme::VKey()
    {
        bool b = true;
        int i = 0;
        BilinearGroup::G2 g2 = BilinearGroup::G2::get_gen();
        // while loops exits until either an invalid X^_i is found, where X^_i = x_i * P^ ; P^=g2
        // or there are no elements to verify anymore
        // Returns false if one element is invalid
        while (b && i < key.sk.size())
        {
            b = key.sk[i] * g2 == key.pk[i];
            i++;
        }
        return b;
    }

    std::vector<BilinearGroup::G1> Scheme::blind_message(BilinearGroup::BN &my, std::vector<BilinearGroup::G1> &M)
    {
        std::vector<BilinearGroup::G1> new_M(M.size());
        std::vector<std::future<void>> futures;
        for (int i = 0; i < M.size(); i++)
        {
            futures.push_back(BilinearGroup::pool.push(
                [&m = M[i], &my, &new_m = new_M[i]](int)
                {
                    new_m = m * my;
                }));
        };
        for (auto &fut : futures)
        {
            fut.wait();
        }
        return new_M;
    };

    void test(int l)
    {
        Scheme sps_eq = Scheme(&l);
        assert(sps_eq.VKey());
        std::vector<BilinearGroup::G1> M(l); // Creates a vector of random Z_p elements, which is the sk
        std::generate(M.begin(), M.end(), []()
                      { return BilinearGroup::G1::rand(); });
        Signature sig = sps_eq.Sign(M);
        assert(sps_eq.Verify(M, sig));
        std::cout << "passed verification" << std::endl;
        BilinearGroup::BN my = BilinearGroup::BN::rand();
        Signature sig_2 = sps_eq.ChgRep(M, sig, my);
        std::cout << "ChgRep successfull" << std::endl;
        std::vector<BilinearGroup::G1> new_M = Scheme::blind_message(my, M);
        assert(sps_eq.Verify(new_M, sig_2));
        std::cout << "passed verification after chgrep" << std::endl;
        std::cout << "all tests passed" << std::endl;
    };

}