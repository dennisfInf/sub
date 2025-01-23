#include "ep.h"
#include <iostream>
extern "C"
{
#include "relic.h"
}

// Most of this class is copy pasted from bilinear_group/group.cpp
// To Do: write cleaner code without having any duplicate code
namespace
{
    class RelicHelper
    {
    public:
        RelicHelper()
        {

            if (core_init() != RLC_OK)
            {
                core_clean();
                return;
            }

            ep_param_set_any_plain();
        };
        ~RelicHelper() { core_clean(); };
    };

    static RelicHelper __helper;
}

namespace EpGroup
{
    ctpl::thread_pool pool{static_cast<int>(std::thread::hardware_concurrency())};

    // print relic configuration
#define init_ep(A)  \
    {               \
        ep_null(A); \
        ep_new(A);  \
    }
#define init_bn(A)  \
    {               \
        bn_null(A); \
        bn_new(A);  \
    }
    void config()
    {
        conf_print();
        ep_param_print();
        BN::get_field_prime_number().print();
        EP g = EP::get_gen();
        g.precompute();
        // LOG("%s", stream.str().c_str());
    }
    std::vector<uint8_t> hash(const uint8_t input[], int len)
    {
        uint8_t hash[RLC_MD_LEN];
        uint8_t buffer[len];
        md_map(hash, input, len);
        return std::vector<uint8_t>(hash, hash + sizeof(hash));
    }

    std::vector<uint8_t> hmac(std::vector<uint8_t> key, std::vector<uint8_t> data)
    {
        uint8_t mac[RLC_MD_LEN];
        md_hmac(mac, data.data(), data.size(), key.data(), key.size());
        return std::vector<uint8_t>(mac, mac + sizeof(mac));
    }

    struct BN::impl
    {
        bn_t element;

        impl() { init_bn(element); };
        impl(const BN &x)
        {
            init_bn(element);
            bn_copy(element, x.pImpl->element);
        }
        impl(int x)
        {
            init_bn(element);
            *this = x;
        }
        impl(uint32_t x)
        {
            init_bn(element);
            *this = x;
        }
        ~impl() { bn_free(element); }
        void operator=(int x)
        {
            if (x < 0)
            {
                bn_set_dig(element, -x);
                bn_neg(element, element);
            }
            else
            {
                bn_set_dig(element, x);
            }
        }
    };
    BN BN::read_bytes(std::vector<uint8_t> bytes, int length)
    {
        BN res;
        bn_read_bin(res.pImpl->element, bytes.data(), length);
        return res;
    }

    BN BN::infty;
    bool BN::initialized_infty = false;

    void BN::rand(BN &x)
    {
        BN mod = EP::get_group_order();

        bn_rand_mod(x.pImpl->element, mod.pImpl->element);
    }

    void BN::rand(BN &x, int bits, bool positive) { bn_rand(x.pImpl->element, positive ? RLC_POS : RLC_NEG, bits); }

    const BN &BN::get_infty()
    {
        if (!initialized_infty)
        {
            infty = BN(0);
            initialized_infty = true;
        }
        return infty;
    }

    const BN &BN::get_group_order() { return EP::get_group_order(); }

    BN BN::rand()
    {
        BN res;
        rand(res);
        return res;
    }

    BN BN::rand(int bits, bool positive)
    {
        BN res;
        rand(res, bits, positive);
        return res;
    }

    BN BN::hash_to_group(const std::vector<uint8_t> &input)
    {
        BN res;
        uint8_t hash[RLC_MD_LEN];
        md_map(hash, input.data(), input.size());
        bn_read_bin(res.pImpl->element, hash, RLC_MD_LEN);
        res %= BN::get_group_order();
        return res;
    }

    BN BN::get_field_prime_number()
    {
        bn_st *prime = &(core_get()->prime);
        BN prime_num;
        bn_copy(prime_num.pImpl->element, prime);
        return prime_num;
    }

    void BN::add(BN &d, const BN &x, const BN &y)
    {
        bn_add(d.pImpl->element, x.pImpl->element, y.pImpl->element);
        d %= BN::get_group_order();
    }
    void BN::add_without_mod(BN &res, BN &d, const BN &x)
    {
        bn_add(res.pImpl->element, d.pImpl->element, x.pImpl->element);
    }

    void BN::sub(BN &d, const BN &x, const BN &y)
    {
        bn_sub(d.pImpl->element, x.pImpl->element, y.pImpl->element);
        d %= BN::get_group_order();
    }

    void BN::div_without_mod(BN &res, BN &d, const BN &x)
    {
        bn_div(res.pImpl->element, d.pImpl->element, x.pImpl->element);
    }
    void BN::sub_without_mod(BN &res, BN &d, const BN &x)
    {
        bn_sub(res.pImpl->element, d.pImpl->element, x.pImpl->element);
    }

    void BN::mul(BN &d, const BN &x, const BN &y)
    {
        bn_mul(d.pImpl->element, x.pImpl->element, y.pImpl->element);
        d %= BN::get_group_order();
    }
    void BN::mul_without_mod(BN &res, BN &d, const BN &x)
    {
        bn_mul(res.pImpl->element, d.pImpl->element, x.pImpl->element);
    }

    void BN::div(BN &d, const BN &x, const BN &y)
    {
        bn_div(d.pImpl->element, x.pImpl->element, y.pImpl->element);
        d %= BN::get_group_order();
    }

    void BN::neg(BN &d, const BN &x)
    {
        bn_neg(d.pImpl->element, x.pImpl->element);
        d %= BN::get_group_order();
    }

    void BN::neg_without_mod(BN &res, const BN &value) { bn_neg(res.pImpl->element, value.pImpl->element); }
    void BN::mod(BN &d, const BN &x, const BN &mod)
    {
        // only reduce if necessary
        if ((x >= mod) || (bn_sign(x.pImpl->element) == RLC_NEG))
        {
            bn_mod(d.pImpl->element, x.pImpl->element, mod.pImpl->element);
        }
        else if (&x != &d)
        {
            d = x;
        }
    }

    void BN::shl(BN &d, const BN &x, int bits) { bn_lsh(d.pImpl->element, x.pImpl->element, bits); }

    void BN::shr(BN &d, const BN &x, int bits) { bn_rsh(d.pImpl->element, x.pImpl->element, bits); }

    void BN::mod_inverse(BN &d, const BN &x, const BN &mod)
    {
        BN tmp;
        BN::mod(tmp, x, mod);
        bn_gcd_ext(tmp.pImpl->element, d.pImpl->element, NULL, tmp.pImpl->element, mod.pImpl->element);
        if (bn_sign(d.pImpl->element) == RLC_NEG)
        {
            bn_add(d.pImpl->element, d.pImpl->element, mod.pImpl->element);
        }
    }

    BN::BN() : pImpl(std::make_unique<impl>()) {}
    BN::BN(const BN &x) : pImpl(std::make_unique<impl>(x)) {}
    BN::BN(int x) : pImpl(std::make_unique<impl>(x)) {}
    BN::BN(uint32_t x) : pImpl(std::make_unique<impl>(x)) {}
    BN::~BN() {}

    void BN::operator=(int x)
    {
        if (x < 0)
        {
            bn_set_dig(pImpl->element, -x);
            bn_neg(pImpl->element, pImpl->element);
        }
        else
        {
            bn_set_dig(pImpl->element, x);
        }
    }

    void BN::operator=(uint32_t x) { bn_set_dig(pImpl->element, x); }

    void BN::operator=(const BN &x) { bn_copy(pImpl->element, x.pImpl->element); }

    uint32_t BN::bitlength() const { return bn_bits(pImpl->element); }

    uint32_t BN::bit(uint32_t index) const { return bn_get_bit(pImpl->element, index); }

    int BN::to_int() const
    {
        dig_t dig;
        bn_get_dig(&dig, pImpl->element);
        int result = (int)dig;
        if (bn_sign(pImpl->element) == RLC_NEG)
        {
            result = -result;
        }
        return result;
    }

    BN BN::operator+(const BN &x) const
    {
        BN res;
        add(res, *this, x);
        return res;
    }

    BN BN::operator-(const BN &x) const
    {
        BN res;
        sub(res, *this, x);
        return res;
    }

    BN BN::operator-() const
    {
        BN res;
        neg(res, *this);
        return res;
    }

    BN BN::operator*(const BN &x) const
    {
        BN res;
        mul(res, *this, x);
        return res;
    }

    EP BN::operator*(const EP &x) const
    {
        EP res;
        EP::mul(res, x, *this);
        return res;
    }

    BN BN::operator/(const BN &x) const
    {
        BN res;
        div(res, *this, x);
        return res;
    }

    BN BN::operator%(const BN &x) const
    {
        BN res;
        while (res < 0)
            res += x;
        mod(res, *this, x);
        return res;
    }

    BN BN::operator<<(int bits) const
    {
        BN res;
        shl(res, *this, bits);
        return res;
    }

    BN BN::operator>>(int bits) const
    {
        BN res;
        shr(res, *this, bits);
        return res;
    }

    void BN::operator+=(const BN &x) { add(*this, *this, x); }

    void BN::operator-=(const BN &x) { sub(*this, *this, x); }

    void BN::operator*=(const BN &x) { mul(*this, *this, x); }

    void BN::operator/=(const BN &x) { div(*this, *this, x); }

    void BN::operator%=(const BN &x) { mod(*this, *this, x); }

    void BN::operator<<=(int bits) { shl(*this, *this, bits); }

    void BN::operator>>=(int bits) { shr(*this, *this, bits); }

    bool BN::operator>(const BN &x) const { return bn_cmp(pImpl->element, x.pImpl->element) == RLC_GT; }

    bool BN::operator<(const BN &x) const { return bn_cmp(pImpl->element, x.pImpl->element) == RLC_LT; }

    bool BN::operator==(const BN &x) const { return bn_cmp(pImpl->element, x.pImpl->element) == RLC_EQ; }

    bool BN::operator!=(const BN &x) const { return !(*this == x); }

    bool BN::operator>=(const BN &x) const
    {
        int cmp = bn_cmp(pImpl->element, x.pImpl->element);
        return (cmp == RLC_EQ) || (cmp == RLC_GT);
    }

    bool BN::operator<=(const BN &x) const
    {
        int cmp = bn_cmp(pImpl->element, x.pImpl->element);
        return (cmp == RLC_EQ) || (cmp == RLC_LT);
    }

    void BN::print() const { bn_print(pImpl->element); }

    uint16_t BN::size() const { return bn_size_bin(pImpl->element) + 3; }

    int BN::serialize(uint8_t *buffer, size_t capacity) const
    {
        if (capacity < size())
        {
            return -1;
        }
        uint16_t len = bn_size_bin(pImpl->element);
        buffer[0] = (uint8_t)(len >> 8);
        buffer[1] = (uint8_t)(len);
        buffer[2] = (bn_sign(pImpl->element) == RLC_POS) ? 0 : 1;
        bn_write_bin(buffer + 3, len, pImpl->element);
        return len + 3;
    }

    int BN::deserialize(uint8_t *buffer)
    {
        uint16_t len = (uint16_t)buffer[0] << 8 | (uint16_t)buffer[1];
        bool negative = buffer[2] == 1;
        bn_read_bin(pImpl->element, buffer + 3, len);
        if (negative)
        {
            neg(*this, *this);
        }
        return len + 3;
    }

    void BN::deserialize(uint8_t *buffer, uint16_t size)
    {
        bn_read_bin(pImpl->element, buffer, size);
    }

    // For this to work the size has to be exactly the size of a deserialized BN
    PRNG::PRNG(std::vector<uint8_t> seed)
    {
        if (RLC_MD_LEN < EP::buffer_size() - 1)
        {
            std::cout << "hash function does not output enough bytes. Required: " << EP::buffer_size() << " but outputs " << RLC_MD_LEN << std::endl;
            exit(1);
        }
        this->last_output = seed;
    }

    EpGroup::BN PRNG::Eval()
    {

        uint8_t output[RLC_MD_LEN];
        md_map(output, last_output.data(), last_output.size());
        this->last_output = std::vector<uint8_t>(output, output + sizeof(output) / sizeof(output[0]));
        // This cuts the output of the hash function to the size of a serialized Z_p element.
        EpGroup::BN res;

        res.deserialize(output, EP::buffer_size() - 1);

        return res;
    }

    struct EP::impl
    {
        ep_t element;
        std::unique_ptr<std::array<ep_t, RLC_EP_TABLE>> table;

        impl() { init_ep(element); }
        impl(const EP &x)
        {
            init_ep(element);
            ep_copy(element, x.pImpl->element);
        }
        ~impl() { ep_free(element); }
    };

    EP EP::infty;
    EP EP::gen;
    BN EP::order;
    bool EP::initialized_infty = false;
    bool EP::initialized_gen = false;
    bool EP::initialized_order = false;

    void EP::precompute()
    {
        if (pImpl->table)
            return;
        pImpl->table = std::make_unique<std::array<ep_t, RLC_EP_TABLE>>();
        ep_mul_pre(pImpl->table->data(), pImpl->element);
    }

    const EP &EP::get_infty()
    {
        if (!initialized_infty)
        {
            ep_set_infty(infty.pImpl->element);
            initialized_infty = true;
        }
        return infty;
    }

    const EP &EP::get_gen()
    {
        if (!initialized_gen)
        {
            ep_curve_get_gen(gen.pImpl->element);
            initialized_gen = true;
        }
        return gen;
    }

    const BN &EP::get_group_order()
    {
        if (!initialized_order)
        {
            ep_curve_get_ord(order.pImpl->element);
            initialized_order = true;
        }
        return order;
    }

    void EP::rand(EP &x) { ep_rand(x.pImpl->element); }

    EP EP::rand()
    {
        EP res;
        rand(res);
        return res;
    }
    EP EP::hash_to_group(const uint8_t *input, int capacity)
    {
        EP res;
        ep_map(res.pImpl->element, input, capacity);
        if (!ep_on_curve(res.pImpl->element))
            throw std::runtime_error("EP::deserialize: point not on curve");
        return res;
    }

    EP EP::hash_to_group(const std::vector<uint8_t> &input)
    {
        EP res;
        ep_map(res.pImpl->element, input.data(), input.size());
        return res;
    }

    std::vector<uint8_t> EP::hash_EP_elements_to_bytes(const std::vector<EP> &input)
    {
        std::vector<uint8_t> serialized_inputs;
        int len = input[0].buffer_size();
        for (auto &el : input)
        {
            uint8_t buffer[len];
            el.serialize(buffer, len);
            serialized_inputs.insert(serialized_inputs.end(), buffer, buffer + len);
        }
        // Checks if the chosen hash function for relic outputs an appropriate amount of pseudorandom bits.
        if (RLC_MD_LEN < BN::get_infty().size())
        {
            std::cout << "Please choose a hash function in the RELIC configuration with output higher than " << BN::get_infty().size() << " bits" << std::endl;
            std::cout << "Current hash function outputs " << RLC_MD_LEN << " bits" << std::endl;
            exit(1);
        }

        uint8_t hash[RLC_MD_LEN];

        md_map(hash, serialized_inputs.data(), serialized_inputs.size());
        std::vector<uint8_t> h(hash, hash + sizeof(hash) / sizeof(hash[0]));

        return h;
    }

    std::vector<uint8_t> EP::hash_from_group()
    {
        int len = this->buffer_size();
        uint8_t buffer[len];
        this->serialize(buffer, len);
        uint8_t hash[RLC_MD_LEN];
        md_map(hash, buffer, len);
        return std::vector<uint8_t>(hash, hash + sizeof(hash));
    }

    void EP::print_coordinates() const
    {
        std::cout << " x coordinate:" << std::endl;
        fp_print(this->pImpl->element->x);
        std::cout << " y coordinate:" << std::endl;
        fp_print(this->pImpl->element->y);
        std::cout << " z coordinate:" << std::endl;
        fp_print(this->pImpl->element->z);
    }

    void EP::norm()
    {
        if (this->pImpl->element->coord != BASIC)
        {
            ep_norm(this->pImpl->element, this->pImpl->element);
        }
    }

    int EP::buffer_size() { return RLC_FP_BYTES + 1; }

    void EP::mul(EP &d, const EP &x, const BN &k)
    {
        if (&x == &EP::gen)
        {
            ep_mul_gen(d.pImpl->element, k.pImpl->element);
        }
        else if (x.pImpl->table)
        {
            ep_mul_fix(d.pImpl->element, x.pImpl->table->data(), k.pImpl->element);
        }
        else
        {
            ep_mul(d.pImpl->element, x.pImpl->element, k.pImpl->element);
        }
    }

    // Calculates the sum of all points multiplied by the respective scalar beforehand
    EP EP::mul_sim(std::vector<EP> points, std::vector<BN> scalars)
    {
        EP res;
        int size = points.size();
        if (points.size() > scalars.size())
        {
            size = scalars.size();
        }
        ep_t p[size];
        bn_t s[size];
        for (int i = 0; i < size; i++)
        {
            ep_copy(p[i], points[i].pImpl->element);
            bn_copy(s[i], scalars[i].pImpl->element);
        }

        ep_mul_sim_lot(res.pImpl->element, p, s, size);
        return res;
    };

    void EP::add(EP &d, const EP &x, const EP &y) { ep_add(d.pImpl->element, x.pImpl->element, y.pImpl->element); }

    void EP::sub(EP &d, const EP &x, const EP &y) { ep_sub(d.pImpl->element, x.pImpl->element, y.pImpl->element); }

    void EP::mul_gen(EP &x, const BN &k) { ep_mul_gen(x.pImpl->element, k.pImpl->element); }

    void EP::neg(EP &d, const EP &x) { ep_neg(d.pImpl->element, x.pImpl->element); }

    EP::EP() : pImpl(std::make_unique<impl>()) {}

    EP::EP(const EP &x) : pImpl(std::make_unique<impl>(x)) {}

    EP::~EP() {}

    bool EP::is_infty() const { return ep_is_infty(pImpl->element) == 1; }

    EP &EP::operator=(const EP &x)
    {
        ep_copy(pImpl->element, x.pImpl->element);
        return *this;
    }

    EP EP::operator+(const EP &x) const
    {
        EP res;
        add(res, *this, x);
        return res;
    }

    EP EP::operator-(const EP &x) const
    {
        EP res;
        sub(res, *this, x);
        return res;
    }

    EP EP::operator-() const
    {
        EP res;
        neg(res, *this);
        return res;
    }

    EP EP::operator*(const BN &k) const
    {
        EP res;
        mul(res, *this, k);
        return res;
    }

    void EP::operator+=(const EP &x) { add(*this, *this, x); }

    void EP::operator-=(const EP &x) { sub(*this, *this, x); }

    void EP::operator*=(const BN &k) { mul(*this, *this, k); }
#define UNCONST(type, var) (*(type *)&(var))

    bool EP::operator==(const EP &x) const
    {
        ep_norm(UNCONST(ep_t, pImpl->element), pImpl->element);
        ep_norm(UNCONST(ep_t, x.pImpl->element), x.pImpl->element);
        return ep_cmp(pImpl->element, x.pImpl->element) == RLC_EQ;
    }

    bool EP::operator!=(const EP &x) const { return !(*this == x); }

    void EP::print() const
    {
        ep_norm(UNCONST(ep_t, pImpl->element), pImpl->element);
        ep_print(pImpl->element);
    }

    uint8_t EP::size() const { return (uint8_t)(ep_size_bin(pImpl->element, true) + 1); }

    int EP::serialize(uint8_t *buffer, size_t capacity) const
    {
        if (is_infty())
        {
            if (capacity < 1)
            {
                return -1;
            }
            buffer[0] = 0;
            return 1;
        }
        if (capacity < RLC_FP_BYTES + 1)
        {
            return -1;
        }

        ep_write_bin(buffer, (int)capacity, pImpl->element, true);

        return RLC_FP_BYTES + 1;
    }

    int EP::deserialize(uint8_t *buffer)
    {
        uint8_t size = buffer[0];
        if (size == 0)
        {
            ep_set_infty(pImpl->element);
            return 1;
        }
        uint8_t read = 0;
        if (size == 4)
        {
            read = 2 * RLC_FP_BYTES + 1;
            ep_read_bin(pImpl->element, buffer, read);
        }
        else
        {
            read = RLC_FP_BYTES + 1;
            ep_read_bin(pImpl->element, buffer, read);
        }
        if (!ep_on_curve(pImpl->element))
            throw std::runtime_error("EP::deserialize: point not on curve");
        return read;
    }

}
