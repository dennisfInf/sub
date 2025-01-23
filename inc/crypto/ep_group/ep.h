#pragma once
#include "thread_pool.h"
#include <iostream>
#include <experimental/propagate_const>

namespace EpGroup
{
    extern ctpl::thread_pool pool;
    void config();
    std::vector<uint8_t> hash(const uint8_t input[], int len);
    std::vector<uint8_t> hmac(std::vector<uint8_t> key, std::vector<uint8_t> data);

    class EP;
    class BN
    {
        friend class EP;

    public:
        BN();
        BN(const BN &x);
        BN(int x);
        BN(uint32_t x);
        ~BN();

        static const BN &get_infty();
        static const BN &get_group_order();

        static void rand(BN &x);
        static BN prf(BN input, int a, int l);

        static BN rand();
        static void rand(BN &x, int bits, bool positive);
        static BN rand(int bits, bool positive);
        static BN hash_to_group(const std::vector<uint8_t> &input);
        static void add(BN &d, const BN &x, const BN &y);
        static void sub(BN &d, const BN &x, const BN &y);
        static void mul(BN &d, const BN &x, const BN &y);
        static void mul_without_mod(BN &res, BN &d, const BN &x);
        static void div(BN &d, const BN &x, const BN &y);
        static void neg(BN &d, const BN &x);
        static void mod(BN &d, const BN &x, const BN &mod);
        static void shl(BN &d, const BN &x, int bits);
        static void shr(BN &d, const BN &x, int bits);
        static void mod_exp(BN &result, const BN &basis, const BN &exp);
        static void mod_inverse(BN &d, const BN &x, const BN &mod);
        static void div_without_mod(BN &res, BN &d, const BN &x);
        static void sub_without_mod(BN &res, BN &d, const BN &x);
        static void add_without_mod(BN &res, BN &d, const BN &x);
        static BN get_field_prime_number();
        void operator=(int x);
        void operator=(uint32_t x);
        void operator=(const BN &x);
        static BN calculate_p_plus_1_over_4(BN &prime);
        static void neg_without_mod(BN &res, const BN &value);
        static BN read_bytes(std::vector<uint8_t> bytes, int length);
        uint32_t bitlength() const;
        uint32_t bit(uint32_t index) const;

        int to_int() const;

        std::string to_string() const;

        BN operator+(const BN &x) const;
        BN operator-(const BN &x) const;
        BN operator-() const;
        BN operator*(const BN &x) const;
        EP operator*(const EP &x) const;
        BN operator/(const BN &x) const;
        BN operator%(const BN &x) const;
        BN operator<<(int bits) const;
        BN operator>>(int bits) const;
        void operator+=(const BN &x);
        void operator-=(const BN &x);
        void operator*=(const BN &x);
        void operator/=(const BN &x);
        void operator%=(const BN &x);
        void operator<<=(int bits);
        void operator>>=(int bits);

        bool operator>(const BN &x) const;
        bool operator<(const BN &x) const;
        bool operator==(const BN &x) const;
        bool operator!=(const BN &x) const;
        bool operator>=(const BN &x) const;
        bool operator<=(const BN &x) const;

        void print() const;

        uint16_t size() const;
        int serialize(uint8_t *buffer, size_t capacity) const;
        int deserialize(uint8_t *buffer);
        void deserialize(uint8_t *buffer, uint16_t size);

        /* PURPOSE of get_words is unclear */
        /* std::vector<uint32_t> get_words() const; */
        struct impl;

        std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

    private:
        static BN infty;
        static bool initialized_infty;
    };

    class PRNG
    {
    public:
        PRNG(std::vector<uint8_t> seed);
        EpGroup::BN Eval();

    private:
        std::vector<uint8_t> last_output;
    };

    class EP
    {
    public:
        static const EP &get_infty();
        static const EP &get_gen();
        static const BN &get_group_order();
        static void rand(EP &x);
        static EP rand();
        static EP hash_to_group(const std::vector<uint8_t> &input);
        static EP hash_to_group(const uint8_t *input, int capacity);

        static void mul_gen(EP &x, const BN &k);
        static void mul(EP &d, const EP &x, const BN &k);
        static void add(EP &d, const EP &x, const EP &y);
        static void sub(EP &d, const EP &x, const EP &y);
        static void neg(EP &d, const EP &x);
        static bool is_point_in_EP(EP &point);
        void print_coordinates() const;
        void norm();

        EP();
        EP(const EP &x);
        EP(int x) : EP(EP::get_gen() * x) {}
        ~EP();

        bool is_infty() const;
        void precompute();

        EP &operator=(const EP &x);

        EP operator+(const EP &x) const;
        EP operator-(const EP &x) const;
        EP operator-() const;
        EP operator*(const BN &x) const;

        void operator+=(const EP &x);
        void operator-=(const EP &x);
        void operator*=(const BN &k);

        bool operator==(const EP &x) const;
        bool operator!=(const EP &x) const;
        static EP mul_sim(std::vector<EP> points, std::vector<BN> scalars);

        void print() const;

        std::string to_string() const;
        uint8_t size() const;
        int serialize(uint8_t *buffer, size_t capacity) const;
        static int buffer_size();
        int deserialize(uint8_t *buffer);

        static std::vector<uint8_t> hash_EP_elements_to_bytes(const std::vector<EP> &input);

        template <typename T>
        static T hash_EP_elements(const std::vector<EP> &input)
        {
            // To Do: Parrelize this
            std::vector<uint8_t> serialized_inputs;
            int len = input[0].buffer_size();
            for (auto &el : input)
            {
                uint8_t buffer[len];
                el.serialize(buffer, len);
                serialized_inputs.insert(serialized_inputs.end(), buffer, buffer + len);
            }
            return T::hash_to_group(serialized_inputs);
        }

        std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> get_coordinates() const;
        std::vector<uint8_t> hash_from_group();
        struct impl;
        std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

    private:
        static EP gen;
        static EP infty;
        static BN order;
        static bool initialized_infty;
        static bool initialized_order;
        static bool initialized_gen;
    };
}