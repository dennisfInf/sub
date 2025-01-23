#include "crypto/privacy_pass/nizk.h"
#include "crypto/ep_group/ep.h"
#include <cassert>

namespace DLEQ
{
    // X is a standardized generator for the configurated elliptic curve and P is a random element which was sampled beforehand.
    // Since we are working in a subgroup with prime order,
    // all points on the curve are generators.
    Proof Prove(const EpGroup::EP &Y, const EpGroup::EP &P, const EpGroup::EP &Q, const EpGroup::BN &k)
    {
        // Sample random element from Z_q
        EpGroup::BN t = EpGroup::BN::rand();

        // Vector of ep points for the hash function H_3
        // A bit more unreadable by using an array instead of single variables, sorry for that. Easier to program with.
        std::vector<EpGroup::EP> ep_points(6);
        // assign ing X to the 0 index
        // Could avoid here to assign X and Y everytime, since both are fixed. But it does not add any significant amount of performance boost.
        ep_points[0] = EpGroup::EP::get_gen();
        ep_points[1] = Y;
        ep_points[2] = P;
        ep_points[3] = Q;
        // Assigning A to the 4th index, A=X*t
        std::future<EpGroup::EP> fut_A = EpGroup::pool.push(
            [&X = ep_points[0], &t](int)
            {
                return X * t;
            });
        // Assigning B to the 5th index, B = P*t

        std::future<EpGroup::EP> fut_B = EpGroup::pool.push(
            [&P, &t](int)
            {
                return P * t;
            });

        ep_points[4] = fut_A.get();
        ep_points[5] = fut_B.get();
        EpGroup::BN c = EpGroup::EP::hash_EP_elements<EpGroup::BN>(ep_points);

        EpGroup::BN s = (t - (c * k));
        return {c, s};
    }

    std::vector<EpGroup::BN> sampleRandomElementsFromPRNG(const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q)
    {
        if (P.size() != Q.size())
        {
            std::cout << "Error in BatchProve: vectors of P's and Q's are not equal in size" << std::endl;
            exit(1);
        };
        std::vector<EpGroup::EP> ep_points;
        // Adds X
        ep_points.push_back(EpGroup::EP::get_gen());
        // Adds Y
        ep_points.push_back(Y);

        // Adds the vector of P
        ep_points.insert(ep_points.end(), P.begin(), P.end());
        // Adds the vector of Q
        ep_points.insert(std::end(ep_points), std::begin(Q), std::end(Q));
        // Hashes the elements contained in the vector ep_points to a bit string element not to Z_p
        // Here the right Hash method has to be specified in the relic configuration, which outputs a bit string with equal
        // length to a Z_p element in big endian format
        // Since the PRNG of relic needs a seed, which is a bit string, we use a pseudo random bit string here and don't convert it to a Z_p by using the big endian format
        // to avoid an extra step.
        std::vector<uint8_t> w = EpGroup::EP::hash_EP_elements_to_bytes(ep_points);
        EpGroup::PRNG prng = EpGroup::PRNG(w);
        std::vector<EpGroup::BN> c(P.size());
        for (int i = 0; i < P.size(); i++)
        {
            c[i] = prng.Eval();
        };
        return c;
    }

    BatchedElements calculateBatchedElements(const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q)
    {
        std::vector<EpGroup::BN> c = sampleRandomElementsFromPRNG(Y, P, Q);
        // Calculates the sum of all (P_i*c_i)
        EpGroup::EP M = EpGroup::EP::mul_sim(P, c);
        EpGroup::EP Z = EpGroup::EP::mul_sim(Q, c);
        return {M, Z};
    }

    Proof BatchProve(const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q, const EpGroup::BN &k)
    {
        // Calculates M and Z
        BatchedElements bElems = calculateBatchedElements(Y, P, Q);
        Proof proof = Prove(Y, bElems.M, bElems.Z, k);
        return proof;
    };

    bool Verify(const Proof &proof, const EpGroup::EP &Y, const EpGroup::EP &P, const EpGroup::EP &Q)
    {
        std::vector<EpGroup::EP> ep_points(6);
        ep_points[0] = EpGroup::EP::get_gen();
        ep_points[1] = Y;
        ep_points[2] = P;
        ep_points[3] = Q;
        // Calculating A' in seperate threads, where left is the left side of the addition symbol
        std::future<EpGroup::EP> fut_A_prime_left = EpGroup::pool.push(
            [&X = ep_points[0], &s = proof.s](int)
            {
                return X * s;
            });

        std::future<EpGroup::EP> fut_A_prime_right = EpGroup::pool.push(
            [&Y, &c = proof.c](int)
            {
                return Y * c;
            });

        // Same for B'
        std::future<EpGroup::EP> fut_B_prime_left = EpGroup::pool.push(
            [&P, &s = proof.s](int)
            {
                return P * s;
            });

        std::future<EpGroup::EP> fut_B_prime_right = EpGroup::pool.push(
            [&Q, &c = proof.c](int)
            {
                return Q * c;
            });

        // Waiting for threads to finish, then adding the result
        std::future<EpGroup::EP> fut_A_prime = EpGroup::pool.push(
            [&fut_A_prime_left, &fut_A_prime_right](int)
            {
                return fut_A_prime_left.get() + fut_A_prime_right.get();
            });

        std::future<EpGroup::EP> fut_B_prime = EpGroup::pool.push(
            [&fut_B_prime_left, &fut_B_prime_right](int)
            {
                return fut_B_prime_left.get() + fut_B_prime_right.get();
            });

        ep_points[4] = fut_A_prime.get();
        ep_points[5] = fut_B_prime.get();
        EpGroup::BN c_prime = EpGroup::EP::hash_EP_elements<EpGroup::BN>(ep_points);
        return c_prime == proof.c;
    }
    bool BatchVerify(const Proof &proof, const EpGroup::EP &Y, const std::vector<EpGroup::EP> &P, const std::vector<EpGroup::EP> &Q)
    {
        BatchedElements bElems = calculateBatchedElements(Y, P, Q);
        return Verify(proof, Y, bElems.M, bElems.Z);
    }

    void verify_prng(EpGroup::EP &Y, std::vector<EpGroup::EP> &P, std::vector<EpGroup::EP> &Q)
    {
        BatchedElements be = calculateBatchedElements(Y, P, Q);
        BatchedElements be2 = calculateBatchedElements(Y, P, Q);
        assert(be.M == be2.M);
        assert(be.Z == be2.Z);
        std::cout
            << "prng verified!" << std::endl;
    }

    void test_dleq()
    {
        // sample random P
        std::cout << "testing dleq" << std::endl;
        EpGroup::BN t = EpGroup::BN::rand();
        int capacity = t.size();
        uint8_t *buffer = new uint8_t[capacity];
        t.serialize(buffer, capacity);
        EpGroup::EP P = EpGroup::EP::hash_to_group(buffer, capacity);
        std::cout << "testing dleq finished" << std::endl;

        // sample random sk
        EpGroup::BN sk = EpGroup::BN::rand();
        // Calculate Y
        EpGroup::EP test = EpGroup::EP::get_gen();
        EpGroup::EP Y = EpGroup::EP::get_gen() * sk;

        // Calculate Q
        EpGroup::EP Q = P * sk;
        // Create proof

        DLEQ::Proof proof = Prove(Y, P, Q, sk);
        std::cout << "finished proof" << std::endl;
        // Verify proof
        assert(Verify(proof, Y, P, Q));
        std::cout << "DLEQ proof verified successfully" << std::endl;
        int amount = 10;
        // sample 10 random generators P_i and multiply them with the sk to get Q_i
        std::vector<EpGroup::EP> P_s(amount);
        std::vector<EpGroup::EP> Q_s(amount);

        for (int i = 0; i < amount; i++)
        {
            P_s[i] = EpGroup::EP::rand();
            Q_s[i] = P_s[i] * sk;
        }
        // Creating batched proof
        DLEQ::Proof batched_proof = BatchProve(Y, P_s, Q_s, sk);
        std::cout << "Batched DLEQ proof created successfully" << std::endl;
        // Verifies the batch proof
        assert(DLEQ::BatchVerify(batched_proof, Y, P_s, Q_s));
        std::cout << "Batched DLEQ proof verified successfully" << std::endl;
    }
}