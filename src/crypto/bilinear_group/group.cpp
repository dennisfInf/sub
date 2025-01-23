#include "group.h"
#include <assert.h>
#include <iostream>
#include <gmp.h>
#include <sstream>
extern "C"
{
#include "relic.h"
}

namespace BilinearGroup
{
  // initialize threadpool
  ctpl::thread_pool pool{static_cast<int>(std::thread::hardware_concurrency())};
  // ctpl::thread_pool pool{6};

  // print relic configuration
  void config()
  {
    conf_print();
    std::cout << "Using " << pool.size() << " threads\n";
    ep_param_print();
    BN::get_field_prime_number().print();
    G1 g1_gen = G1::get_gen();
    g1_gen.precompute();
    G2 g2_gen = G2::get_gen();
    g2_gen.precompute();
    // LOG("%s", stream.str().c_str());
  }
  void intToByteArray(int value, uint8_t *byteArray, int capacity)
  {
    for (int i = 0; i < capacity && i < sizeof(int); ++i)
    {
      byteArray[i] = (value >> (i * 8)) & 0xFF;
    }
  }

  std::vector<uint8_t> hash(const uint8_t input[], int len)
  {
    uint8_t hash[RLC_MD_LEN];
    uint8_t buffer[len];
    md_map(hash, input, len);
    return std::vector<uint8_t>(hash, hash + sizeof(hash));
  }

  GT operator*(const G1 &g1, const G2 &g2) { return GT::map(g1, g2); }

  // helper to automatically initialize/free the RELIC core
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
        ep_param_set_any_pairf();
      };
      ~RelicHelper() { core_clean(); };
    };

    static RelicHelper __helper;
  } // namespace

#define init_bn(A) \
  {                \
    bn_null(A);    \
    bn_new(A);     \
  }
#define init_g1(A) \
  {                \
    g1_null(A);    \
    g1_new(A);     \
  }
#define init_g2(A) \
  {                \
    g2_null(A);    \
    g2_new(A);     \
  }
#define init_gt(A) \
  {                \
    gt_null(A);    \
    gt_new(A);     \
  }

// ugly but required hack as RELIC is quite inconsistent with const sometimes
#define UNCONST(type, var) (*(type *)&(var))

  struct FP::impl
  {
    fp_t element;
    impl()
    {
      fp_null(element);
      fp_new(element);
    }
    impl(int x)
    {
      fp_null(element);
      fp_new(element);
      fp_set_dig(element, x);
    };
    impl(const FP &x)
    {
      fp_null(element);
      fp_new(element);
      fp_copy(element, x.pImpl->element);
    };
    ~impl() { fp_free(element); }
  };

  FP::FP() : pImpl(std::make_unique<impl>()) {}
  FP::FP(int x) : pImpl(std::make_unique<impl>(x)) {}
  FP::FP(const FP &x) : pImpl(std::make_unique<impl>(x)) {}
  void FP::operator=(const FP &x) { fp_copy(pImpl->element, x.pImpl->element); }

  FP::~FP() {}
  void FP::increment() { fp_add_dig(pImpl->element, pImpl->element, 1); }

  // ############################################
  //     BN
  // ############################################
  struct BN::impl
  {
    bn_t element;

    impl() { init_bn(element); }
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
    BN mod = G1::get_group_order();

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

  const BN &BN::get_group_order() { return G1::get_group_order(); }

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
  BN BN::prf(BN input, int a, int l)
  {
    int capacity = input.size();
    uint8_t *buffer = new uint8_t[capacity + sizeof(int)];
    input.serialize(buffer, capacity);
    intToByteArray(a, buffer + capacity, sizeof(int));
    uint8_t hash[RLC_MD_LEN];
    md_map(hash, buffer, capacity + sizeof(int));
    BN res;
    bn_read_bin(res.pImpl->element, hash, l);
    res.print();
    res %= BN::get_group_order();
    delete[] buffer;
    return res;
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

  std::string BN::to_string() const
  {
    std::stringstream ss(std::stringstream::in | std::stringstream::out | std::stringstream::binary);
    ss << *this;
    char buf[this->size() + 1];
    ss.read(buf, this->size() + 1);
    std::string erg(buf, sizeof(buf));
    return erg;
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

  G1 BN::operator*(const G1 &x) const
  {
    G1 res;
    G1::mul(res, x, *this);
    return res;
  }

  G2 BN::operator*(const G2 &x) const
  {
    G2 res;
    G2::mul(res, x, *this);
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

  /* std::vector<uint32_t> BN::get_words() const */
  /* { */
  /*     uint32_t size = bn_size_raw(element); */
  /*     dig_t array[size]; */

  /*     bn_write_raw(array, size, element); */

  /* std::vector<uint32_t> res; */
  /*     res.reserve(size); */

  /*     for (uint32_t i = 0; i < size; ++i) */
  /*     { */
  /*         res.push_back((uint32_t)array[size - 1 - i]); */
  /*     } */

  /*     return res; */
  /* } */

  // ############################################
  //     G1
  // ############################################
  std::vector<uint8_t> write_fp_to_bytes(const fp_st &fp)
  {
    bn_t n;
    bn_null(n);
    bn_new(n);
    fp_prime_back(n, fp);
    uint16_t len = bn_size_bin(n);
    uint8_t buffer[len + 3];
    buffer[0] = (uint8_t)(len >> 8);
    buffer[1] = (uint8_t)(len);
    buffer[2] = 0;
    bn_write_bin(buffer + 3, len, n);
    bn_free(n);
    return std::vector<uint8_t>(buffer, buffer + sizeof(buffer));
  }

  void bytes_to_fp(fp_st &fp, const std::vector<uint8_t> &bytes)
  {
    bn_t n;
    bn_null(n);
    bn_new(n);

    bn_read_bin(n, bytes.data(), bytes.size());
    fp_prime_conv(fp, n);
    bn_free(n);
  }

  struct G1::impl
  {
    g1_t element;
    std::unique_ptr<std::array<g1_t, RLC_G1_TABLE>> table;

    impl() { init_g1(element); }
    impl(const G1 &x)
    {
      init_g1(element);
      g1_copy(element, x.pImpl->element);
    }
    ~impl() { g1_free(element); }
  };

  G1 G1::infty;
  G1 G1::gen;
  BN G1::order;
  bool G1::initialized_infty = false;
  bool G1::initialized_gen = false;
  bool G1::initialized_order = false;

  void G1::precompute()
  {
    if (pImpl->table)
      return;
    pImpl->table = std::make_unique<std::array<g1_t, RLC_G1_TABLE>>();
    g1_mul_pre(pImpl->table->data(), pImpl->element);
  }

  const G1 &G1::get_infty()
  {
    if (!initialized_infty)
    {
      g1_set_infty(infty.pImpl->element);
      initialized_infty = true;
    }
    return infty;
  }

  const G1 &G1::get_gen()
  {
    if (!initialized_gen)
    {
      g1_get_gen(gen.pImpl->element);
      initialized_gen = true;
    }
    return gen;
  }

  const BN &G1::get_group_order()
  {
    if (!initialized_order)
    {
      g1_get_ord(order.pImpl->element);
      initialized_order = true;
    }
    return order;
  }

  void G1::rand(G1 &x) { g1_rand(x.pImpl->element); }

  G1 G1::rand()
  {
    G1 res;
    rand(res);
    return res;
  }
  G1 G1::hash_to_group(const std::vector<uint8_t> &input)
  {
    G1 res;
    g1_map(res.pImpl->element, input.data(), input.size());
    return res;
  }

  std::vector<uint8_t> G1::hash_from_group()
  {
    int len = this->buffer_size();
    uint8_t buffer[len];
    this->serialize(buffer, len);
    uint8_t hash[RLC_MD_LEN];
    md_map(hash, buffer, len);
    return std::vector<uint8_t>(hash, hash + sizeof(hash));
  }

  void G1::print_coordinates() const
  {
    std::cout << " x coordinate:" << std::endl;
    fp_print(this->pImpl->element->x);
    std::cout << " y coordinate:" << std::endl;
    fp_print(this->pImpl->element->y);
    std::cout << " z coordinate:" << std::endl;
    fp_print(this->pImpl->element->z);
  }

  void G1::norm()
  {
    if (this->pImpl->element->coord != BASIC)
    {
      g1_norm(UNCONST(g1_t, this->pImpl->element), this->pImpl->element);
    }
  }
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> G1::get_coordinates() const
  {
    if (this->pImpl->element->coord != BASIC)
    {
      g1_norm(UNCONST(g1_t, this->pImpl->element), this->pImpl->element);
    }
    std::vector<uint8_t> x_bytes = write_fp_to_bytes(this->pImpl->element->x);
    std::vector<uint8_t> y_bytes = write_fp_to_bytes(this->pImpl->element->y);

    return {x_bytes, y_bytes};
  };

  int G1::buffer_size() const { return g1_size_bin(this->pImpl->element, 1); }

  void G1::mul(G1 &d, const G1 &x, const BN &k)
  {
    if (&x == &G1::gen)
    {
      g1_mul_gen(d.pImpl->element, k.pImpl->element);
    }
    else if (x.pImpl->table)
    {
      g1_mul_fix(d.pImpl->element, x.pImpl->table->data(), k.pImpl->element);
    }
    else
    {
      g1_mul(d.pImpl->element, x.pImpl->element, k.pImpl->element);
    }
  }

  void G1::add(G1 &d, const G1 &x, const G1 &y) { g1_add(d.pImpl->element, x.pImpl->element, y.pImpl->element); }

  void G1::sub(G1 &d, const G1 &x, const G1 &y) { g1_sub(d.pImpl->element, x.pImpl->element, y.pImpl->element); }

  void G1::mul_gen(G1 &x, const BN &k) { g1_mul_gen(x.pImpl->element, k.pImpl->element); }

  void G1::neg(G1 &d, const G1 &x) { g1_neg(d.pImpl->element, x.pImpl->element); }

  G1::G1() : pImpl(std::make_unique<impl>()) {}

  G1::G1(const G1 &x) : pImpl(std::make_unique<impl>(x)) {}

  G1::~G1() {}

  bool G1::is_infty() const { return g1_is_infty(pImpl->element) == 1; }

  G1 &G1::operator=(const G1 &x)
  {
    g1_copy(pImpl->element, x.pImpl->element);
    return *this;
  }

  G1 G1::operator+(const G1 &x) const
  {
    G1 res;
    add(res, *this, x);
    return res;
  }

  G1 G1::operator-(const G1 &x) const
  {
    G1 res;
    sub(res, *this, x);
    return res;
  }

  G1 G1::operator-() const
  {
    G1 res;
    neg(res, *this);
    return res;
  }

  G1 G1::operator*(const BN &k) const
  {
    G1 res;
    mul(res, *this, k);
    return res;
  }

  void G1::operator+=(const G1 &x) { add(*this, *this, x); }

  void G1::operator-=(const G1 &x) { sub(*this, *this, x); }

  void G1::operator*=(const BN &k) { mul(*this, *this, k); }

  bool G1::operator==(const G1 &x) const
  {
    g1_norm(UNCONST(g1_t, pImpl->element), pImpl->element);
    g1_norm(UNCONST(g1_t, x.pImpl->element), x.pImpl->element);
    return g1_cmp(pImpl->element, x.pImpl->element) == RLC_EQ;
  }

  bool G1::operator!=(const G1 &x) const { return !(*this == x); }

  void G1::print() const
  {
    g1_norm(UNCONST(g1_t, pImpl->element), pImpl->element);
    g1_print(pImpl->element);
  }

  std::string G1::to_string() const
  {
    std::stringstream ss(std::stringstream::in | std::stringstream::out | std::stringstream::binary);
    ss << *this;
    char buf[this->size() + 1];
    ss.read(buf, this->size() + 1);
    std::string erg(buf, sizeof(buf));
    return erg;
  }

  uint8_t G1::size() const { return (uint8_t)(g1_size_bin(pImpl->element, true) + 1); }

  int G1::serialize(uint8_t *buffer, size_t capacity) const
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
    g1_write_bin(buffer, (int)capacity, pImpl->element, true);
    return RLC_FP_BYTES + 1;
  }

  int G1::deserialize(uint8_t *buffer)
  {
    uint8_t size = buffer[0];
    if (size == 0)
    {
      g1_set_infty(pImpl->element);
      return 1;
    }
    uint8_t read = 0;
    if (size == 4)
    {
      read = 2 * RLC_FP_BYTES + 1;
      g1_read_bin(pImpl->element, buffer, read);
    }
    else
    {
      read = RLC_FP_BYTES + 1;
      g1_read_bin(pImpl->element, buffer, read);
    }
    if (!g1_is_valid(pImpl->element))
      throw std::runtime_error("G1::deserialize: point not on curve");
    return read;
  }

  // ############################################
  //     G2
  // ############################################
  struct G2::impl
  {
    g2_t element;
    std::shared_ptr<std::array<g2_t, RLC_G2_TABLE>> table;

    impl() { init_g2(element); }
    impl(const impl &x)
    {
      init_g2(element);
      g2_copy(element, UNCONST(g2_t, x.element));
      table = x.table;
    }
    ~impl() { g2_free(element); }
  };
  G2 G2::infty;
  G2 G2::gen;
  bool G2::initialized_infty = false;
  bool G2::initialized_gen = false;

  const G2 &G2::get_infty()
  {
    if (!initialized_infty)
    {
      g2_set_infty(infty.pImpl->element);
      initialized_infty = true;
    }
    return infty;
  }

  void G2::precompute()
  {
    if (pImpl->table)
      return;
    pImpl->table = std::make_shared<std::array<g2_t, RLC_G2_TABLE>>();
    g2_mul_pre(pImpl->table->data(), pImpl->element);
  }

  const G2 &G2::get_gen()
  {
    if (!initialized_gen)
    {
      g2_get_gen(gen.pImpl->element);
      initialized_gen = true;
    }
    return gen;
  }

  const BN &G2::get_group_order() { return G1::get_group_order(); }

  void G2::rand(G2 &x) { g2_rand(x.pImpl->element); }

  G2 G2::rand()
  {
    G2 res;
    rand(res);
    return res;
  }

  G2 G2::hash_to_group(const std::vector<uint8_t> &input)
  {
    G2 res;
    g2_map(res.pImpl->element, input.data(), input.size());
    return res;
  }

  void G2::mul(G2 &d, const G2 &x, const BN &k)
  {
    if (&x == &gen)
    {
      g2_mul_gen(d.pImpl->element, UNCONST(bn_t, k.pImpl->element));
    }
    else if (x.pImpl->table)
    {
      g2_mul_fix(d.pImpl->element, x.pImpl->table->data(), UNCONST(bn_t, k.pImpl->element));
    }
    else
    {
      g2_mul(d.pImpl->element, UNCONST(g2_t, x.pImpl->element), k.pImpl->element);
    }
  }

  void G2::add(G2 &d, const G2 &x, const G2 &y)
  {
    g2_add(d.pImpl->element, UNCONST(g2_t, x.pImpl->element), UNCONST(g2_t, y.pImpl->element));
  }

  void G2::sub(G2 &d, const G2 &x, const G2 &y)
  {
    g2_sub(d.pImpl->element, UNCONST(g2_t, x.pImpl->element), UNCONST(g2_t, y.pImpl->element));
  }

  void G2::mul_gen(G2 &x, const BN &k) { g2_mul_gen(x.pImpl->element, UNCONST(bn_t, k.pImpl->element)); }

  void G2::neg(G2 &d, const G2 &x) { g2_neg(d.pImpl->element, UNCONST(g2_t, x.pImpl->element)); }

  G2::G2() : pImpl(std::make_unique<impl>()) {}

  G2::G2(const G2 &x) : pImpl(std::make_unique<impl>(*x.pImpl)) {}

  G2::~G2() {}

  bool G2::is_infty() const { return g2_is_infty(UNCONST(g2_t, pImpl->element)) == 1; }

  G2 &G2::operator=(const G2 &x)
  {
    g2_copy(pImpl->element, UNCONST(g2_t, x.pImpl->element));
    return *this;
  }

  G2 G2::operator+(const G2 &x) const
  {
    G2 res;
    add(res, *this, x);
    return res;
  }

  G2 G2::operator-(const G2 &x) const
  {
    G2 res;
    sub(res, *this, x);
    return res;
  }

  G2 G2::operator-() const
  {
    G2 res;
    neg(res, *this);
    return res;
  }

  G2 G2::operator*(const BN &k) const
  {
    G2 res;
    mul(res, *this, k);
    return res;
  }

  void G2::operator+=(const G2 &x) { add(*this, *this, x); }

  void G2::operator-=(const G2 &x) { sub(*this, *this, x); }

  void G2::operator*=(const BN &k) { mul(*this, *this, k); }

  bool G2::operator==(const G2 &x) const
  {
    g2_norm(UNCONST(g2_t, pImpl->element), UNCONST(g2_t, pImpl->element));
    g2_norm(UNCONST(g2_t, x.pImpl->element), UNCONST(g2_t, x.pImpl->element));
    return g2_cmp(UNCONST(g2_t, pImpl->element), UNCONST(g2_t, x.pImpl->element)) == RLC_EQ;
  }

  bool G2::operator!=(const G2 &x) const { return !(*this == x); }

  void G2::print() const
  {
    g2_norm(UNCONST(g2_t, pImpl->element), UNCONST(g2_t, pImpl->element));
    g2_print(UNCONST(g2_t, pImpl->element));
  }

  std::string G2::to_string() const
  {
    std::stringstream ss(std::stringstream::in | std::stringstream::out | std::stringstream::binary);
    ss << *this;
    char buf[this->size() + 1];
    ss.read(buf, this->size() + 1);
    std::string erg(buf, sizeof(buf));
    return erg;
  }

  uint8_t G2::size() const { return (uint8_t)(g2_size_bin(UNCONST(g2_t, pImpl->element), true) + 1); }

  int G2::serialize(uint8_t *buffer, size_t capacity) const
  {
    // uint8_t bytes = size();
    if (is_infty())
    {
      if (capacity < 1)
      {
        return -1;
      }
      buffer[0] = 0;
      return 1;
    }
    if (capacity < 2 * RLC_FP_BYTES + 1)
    {
      return -1;
    }
    g2_write_bin(buffer, (int)capacity, UNCONST(g2_t, pImpl->element), true);
    return 2 * RLC_FP_BYTES + 1;
  }

  int G2::deserialize(uint8_t *buffer)
  {
    uint8_t size = buffer[0];
    if (size == 0)
    {
      g2_set_infty(pImpl->element);
      return 1;
    }
    uint8_t read = 0;
    if (size == 4)
    {
      read = 4 * RLC_FP_BYTES + 1;
      g2_read_bin(pImpl->element, buffer, read);
    }
    else
    {
      read = 2 * RLC_FP_BYTES + 1;
      g2_read_bin(pImpl->element, buffer, read);
    }
    if (!g2_is_valid(pImpl->element))
      throw std::runtime_error("G2::deserialize: point not on curve");
    return read;
  }
  // ############################################
  //     GT
  // ############################################
  struct GT::impl
  {
    gt_t element;
    impl() { init_gt(element); }
    impl(const GT &x)
    {
      init_gt(element);
      gt_copy(element, UNCONST(gt_t, x.pImpl->element));
    }
    ~impl() { gt_free(element); }
  };
  GT GT::unity;
  GT GT::gen;
  bool GT::initialized_unity = false;
  bool GT::initialized_gen = false;

  const GT &GT::get_unity()
  {
    if (!initialized_unity)
    {
      gt_set_unity(unity.pImpl->element);
      initialized_unity = true;
    }
    return unity;
  }

  const GT &GT::get_gen()
  {
    if (!initialized_gen)
    {
      gt_get_gen(gen.pImpl->element);
      initialized_gen = true;
    }
    return gen;
  }

  void GT::mul(GT &d, const GT &x, const BN &k)
  {
    gt_exp(d.pImpl->element, UNCONST(gt_t, x.pImpl->element), UNCONST(bn_t, k.pImpl->element));
  }

  void GT::add(GT &d, const GT &x, const GT &y)
  {
    gt_mul(d.pImpl->element, UNCONST(gt_t, x.pImpl->element), UNCONST(gt_t, y.pImpl->element));
  }

  void GT::map(GT &e, const G1 &x, const G2 &y)
  {
    pc_map(e.pImpl->element, UNCONST(g1_t, x.pImpl->element), UNCONST(g2_t, y.pImpl->element));
  }

  GT GT::map(const G1 &x, const G2 &y)
  {
    GT res;
    map(res, x, y);
    return res;
  }

  GT::GT() : pImpl(std::make_unique<impl>()) {}
  GT::GT(const GT &x) : pImpl(std::make_unique<impl>(x)) {}

  GT::~GT() {}

  GT &GT::operator=(const GT &x)
  {
    gt_copy(pImpl->element, UNCONST(gt_t, x.pImpl->element));
    return *this;
  }

  GT GT::operator+(const GT &x) const
  {
    GT res;
    add(res, *this, x);
    return res;
  }

  GT GT::operator*(const BN &x) const
  {
    GT res;
    mul(res, *this, x);
    return res;
  }

  void GT::operator+=(const GT &x) { add(*this, *this, x); }

  void GT::operator*=(const BN &x) { mul(*this, *this, x); }

  bool FP::operator==(const FP &x) const { return fp_cmp(pImpl->element, x.pImpl->element) == RLC_EQ; };
  bool GT::operator==(const GT &x) const
  {
    return gt_cmp(UNCONST(gt_t, pImpl->element), UNCONST(gt_t, x.pImpl->element)) == RLC_EQ;
  }

  bool GT::operator!=(const GT &x) const { return !(*this == x); }

  void GT::print() const { gt_print(UNCONST(gt_t, pImpl->element)); }
  void BN::mod_exp(BN &result, const BN &basis, const BN &exp)
  {
    bn_mxp_slide(result.pImpl.get()->element, basis.pImpl.get()->element, exp.pImpl.get()->element,
                 BN::get_field_prime_number().pImpl->element);
  }
  // Koblitz encoding does not work for BLS12-381
  BN BN::calculate_p_plus_1_over_4(BN &prime)
  {
    bn_t p_plus_1_over_4, p;
    bn_null(p_plus_1_over_4);
    bn_new(p_plus_1_over_4);
    bn_add_dig(p_plus_1_over_4, prime.pImpl->element, 1);
    BN elem;
    bn_hlv(elem.pImpl.get()->element, p_plus_1_over_4);
    bn_hlv(elem.pImpl.get()->element, elem.pImpl.get()->element);
    return elem;
  }
  void init_g1_element(G1 &point, FP &x, FP &y)
  {
    fp_copy(point.pImpl->element->x, x.pImpl->element);
    fp_copy(point.pImpl->element->y, y.pImpl->element);
    fp_set_dig(point.pImpl->element->z, 1); // Set the z-coordinate to 1 for affine coordinates
    point.pImpl->element->coord = BASIC;    // Set the point to be normalized
  }

  FP calculate_y_squared(FP &x, BN &prime)
  {
    // Calculate x^3 + 2
    FP y_squared;

    fp_exp(y_squared.pImpl->element, x.pImpl->element, BN(3).pImpl->element);
    fp_add_dig(y_squared.pImpl->element, y_squared.pImpl->element, 2);
    return y_squared;
  }

  bool is_quadratic_residue(FP &quadratic_residue, BN &p_plus_1_over_4, FP &result)
  {
    fp_exp(result.pImpl->element, quadratic_residue.pImpl->element, p_plus_1_over_4.pImpl->element);
    FP result_squared;
    fp_exp(result_squared.pImpl->element, result.pImpl->element, BN(2).pImpl->element);
    if (result_squared == quadratic_residue)
    {
      return true;
    }
    else
    {
      return false;
    }
  }

  bool G1::get_G1_point(FP &x, G1 &point, BN &prime)
  {
    // Requires that the prime number p is congruent to 3 mod 4
    FP y_squared = calculate_y_squared(x, prime);
    FP y;
    BN p_plus_1_over_4 = BN::calculate_p_plus_1_over_4(prime);
    bool is_quadratic = is_quadratic_residue(y_squared, p_plus_1_over_4, y);
    if (is_quadratic)
    {
      init_g1_element(point, x, y);
      if (!g1_is_valid(point.pImpl->element))
      {
        std::cout << "G1 element in encoding is invalid" << std::endl;
        return true;
      }
      return false;
    }
    else
    {
      return true;
    }
  }

  G1 G1::koblitz_encode_message(const FP &message)
  {
    BN prime = BN::get_field_prime_number();
    if (prime % 4 == 1)
      throw std::runtime_error("is_quadratic_residue: p must be congruent to 3 mod 4");
    // ommitted the check for the message being < p/1000-1, because relic does not provide an interface to convert a bn_t
    // to a fp_t, and
    //  a fp_t is required to initialize a G1 point.
    if (!fp_is_zero(message.pImpl->element))
    {
      int counter = 0;
      FP x;
      fp_mul_dig(x.pImpl->element, message.pImpl->element, 1000);
      G1 point;
      while (G1::get_G1_point(x, point, prime) && counter < 1000)
      {
        fp_add_dig(x.pImpl->element, x.pImpl->element, counter);
        counter++;
      }
      return point;
    }
    else
    {
      throw std::invalid_argument("Message is either not positive or not smaller than p/1000 -1");
    }
  };

  // return (uint8_t)(g2_size_bin(UNCONST(g2_t, pImpl->element), true) + 1);
  uint16_t GT::size() const
  {
    return (uint16_t)(gt_size_bin(UNCONST(gt_t, pImpl->element), true));
  };
  bool GT::is_unity() const
  {
    return gt_is_unity(UNCONST(gt_t, pImpl->element)) == 1;
  }

  int GT::serialize(uint8_t *buffer, size_t capacity) const
  {
    if (is_unity())
    {
      if (capacity < 1)
      {
        return -1;
      }
      buffer[0] = 0;
      return 1;
    }
    if (capacity < 8 * RLC_FP_BYTES)
    {
      return -1;
    }
    gt_write_bin(buffer, (int)capacity, UNCONST(gt_t, pImpl->element), true);
    return 8 * RLC_FP_BYTES;
  };

  // Don't know if this method works for all pairing curves, but I think it don't

  int GT::deserialize(uint8_t *buffer)
  {
    uint16_t read = 8 * RLC_FP_BYTES;

    gt_read_bin(UNCONST(gt_t, pImpl->element), buffer, read);
    if (!gt_is_valid(pImpl->element))
      throw std::runtime_error("GT::deserialize: point not on curve");
    return read;
  };

}
std::istream &operator>>(std::istream &is, BilinearGroup::BN &e)
{
  uint8_t size;
  is.read(reinterpret_cast<char *>(&size), sizeof(size));
  uint8_t buffer[size];
  is.read(reinterpret_cast<char *>(buffer), sizeof(buffer));
  e.deserialize(buffer);
  return is;
}

std::istream &operator>>(std::istream &is, BilinearGroup::G1 &e)
{
  uint8_t size;
  is.read(reinterpret_cast<char *>(&size), sizeof(size));
  uint8_t buffer[size];
  is.read(reinterpret_cast<char *>(buffer), sizeof(buffer));
  e.deserialize(buffer);
  return is;
}

std::istream &operator>>(std::istream &is, BilinearGroup::G2 &e)
{
  uint8_t size;
  is.read(reinterpret_cast<char *>(&size), sizeof(size));
  uint8_t buffer[size];
  is.read(reinterpret_cast<char *>(buffer), sizeof(buffer));
  e.deserialize(buffer);
  return is;
}

std::ostream &operator<<(std::ostream &os, BilinearGroup::BN const &e)
{
  uint8_t element_size = e.size();
  uint8_t buffer[element_size];
  e.serialize(buffer, element_size);
  os << element_size;
  os.write((char *)buffer, sizeof(buffer));
  return os;
}

std::ostream &operator<<(std::ostream &os, BilinearGroup::G1 const &e)
{
  uint8_t element_size = e.size();
  uint8_t buffer[element_size];
  e.serialize(buffer, element_size);
  os << element_size;
  os.write((char *)buffer, sizeof(buffer));
  return os;
}

std::ostream &operator<<(std::ostream &os, BilinearGroup::G2 const &e)
{
  uint8_t element_size = e.size();
  uint8_t buffer[element_size];
  e.serialize(buffer, element_size);
  os << element_size;
  os.write((char *)buffer, sizeof(buffer));
  return os;
}
