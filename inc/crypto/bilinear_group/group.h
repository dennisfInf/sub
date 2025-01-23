#pragma once
#include "thread_pool.h"
#include <array>
#include <experimental/propagate_const>
#include <fstream>
#include <memory>
#include <sstream>
#include <vector>
namespace BilinearGroup
{
  extern ctpl::thread_pool pool;
  class G1;
  class G2;
  class GT;

  void config();

  std::vector<uint8_t> hash(const uint8_t input[], int len);
  class BN
  {
    friend class G1;
    friend class G2;
    friend class GT;

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
    G1 operator*(const G1 &x) const;
    G2 operator*(const G2 &x) const;
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

    /* PURPOSE of get_words is unclear */
    /* std::vector<uint32_t> get_words() const; */
    struct impl;

    std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

  private:
    static BN infty;
    static bool initialized_infty;
  };
  class FP
  {
  public:
    FP();
    FP(int x);
    FP(const FP &x);

    ~FP();
    bool operator==(const FP &x) const;
    void operator=(const FP &x);

    void increment();
    struct impl;
    std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

  private:
  };
  class G1
  {
    friend class GT;

  public:
    static const G1 &get_infty();
    static const G1 &get_gen();
    static const BN &get_group_order();
    static G1 koblitz_encode_message(const FP &message);
    static void rand(G1 &x);
    static G1 rand();
    static G1 hash_to_group(const std::vector<uint8_t> &input);
    static void mul_gen(G1 &x, const BN &k);
    static void mul(G1 &d, const G1 &x, const BN &k);
    static void add(G1 &d, const G1 &x, const G1 &y);
    static void sub(G1 &d, const G1 &x, const G1 &y);
    static void neg(G1 &d, const G1 &x);
    static bool get_G1_point(FP &x, G1 &point, BN &prime);
    static bool is_point_in_G1(G1 &point);
    void print_coordinates() const;
    void norm();

    G1();
    G1(const G1 &x);
    G1(int x) : G1(G1::get_gen() * x) {}
    ~G1();

    bool is_infty() const;
    void precompute();

    G1 &operator=(const G1 &x);

    G1 operator+(const G1 &x) const;
    G1 operator-(const G1 &x) const;
    G1 operator-() const;
    G1 operator*(const BN &x) const;

    void operator+=(const G1 &x);
    void operator-=(const G1 &x);
    void operator*=(const BN &k);

    bool operator==(const G1 &x) const;
    bool operator!=(const G1 &x) const;

    void print() const;

    std::string to_string() const;
    uint8_t size() const;
    int serialize(uint8_t *buffer, size_t capacity) const;
    int buffer_size() const;
    int deserialize(uint8_t *buffer);

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> get_coordinates() const;
    std::vector<uint8_t> hash_from_group();
    struct impl;
    std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

  private:
    static G1 gen;
    static G1 infty;
    static BN order;
    static bool initialized_infty;
    static bool initialized_order;
    static bool initialized_gen;
  };

  class G2
  {
    friend class GT;

  public:
    static const G2 &get_infty();
    static const G2 &get_gen();
    static const BN &get_group_order();

    static void rand(G2 &x);
    static G2 rand();
    static G2 hash_to_group(const std::vector<uint8_t> &input);

    static void mul_gen(G2 &x, const BN &k);
    static void mul(G2 &d, const G2 &x, const BN &k);
    static void add(G2 &d, const G2 &x, const G2 &y);
    static void sub(G2 &d, const G2 &x, const G2 &y);
    static void neg(G2 &d, const G2 &x);

    G2();
    G2(const G2 &x);
    ~G2();
    G2(int x) : G2(G2::get_gen() * x) {}

    bool is_infty() const;
    void precompute();

    G2 &operator=(const G2 &x);

    G2 operator+(const G2 &x) const;
    G2 operator-(const G2 &x) const;
    G2 operator-() const;
    G2 operator*(const BN &x) const;

    void operator+=(const G2 &x);
    void operator-=(const G2 &x);
    void operator*=(const BN &k);

    bool operator==(const G2 &x) const;
    bool operator!=(const G2 &x) const;

    void print() const;

    std::string to_string() const;

    uint8_t size() const;
    int serialize(uint8_t *buffer, size_t capacity) const;
    int deserialize(uint8_t *buffer);

  private:
    struct impl;
    std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

    static G2 gen;
    static G2 infty;
    static bool initialized_infty;
    static bool initialized_gen;
  };

  class GT
  {
  public:
    static const GT &get_unity();
    static const GT &get_gen();

    static void mul(GT &d, const GT &x, const BN &k);
    static void add(GT &d, const GT &x, const GT &y);
    static void map(GT &e, const G1 &x, const G2 &y);
    static GT map(const G1 &x, const G2 &y);

    GT();
    GT(const GT &x);
    ~GT();
    GT(int x) : GT(GT::get_gen() * x) {}

    GT &operator=(const GT &x);

    GT operator+(const GT &x) const;
    GT operator*(const BN &x) const;
    void operator+=(const GT &x);
    void operator*=(const BN &k);

    bool operator==(const GT &x) const;
    bool operator!=(const GT &x) const;

    void print() const;
    bool is_unity() const;
    uint16_t size() const;
    int serialize(uint8_t *buffer, size_t capacity) const;
    int deserialize(uint8_t *buffer);

  private:
    struct impl;
    std::experimental::propagate_const<std::unique_ptr<impl>> pImpl;

    static GT gen;
    static GT unity;
    static bool initialized_unity;
    static bool initialized_gen;
  };

  GT operator*(const G1 &g1, const G2 &g2);
} // namespace BilinearGroup

namespace std
{
  namespace
  {
    size_t djb_hash(uint8_t *buf, size_t len)
    {
      size_t hash = 5381;

      for (size_t i = 0; i < len; ++i)
        hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */

      return hash;
    }
  } // namespace

  template <>
  struct hash<BilinearGroup::G1>
  {
    size_t operator()(const BilinearGroup::G1 &k) const
    {
      size_t s = k.size();
      std::vector<uint8_t> buf(s);
      k.serialize(buf.data(), s);

      return djb_hash(buf.data(), s);
    }
  };

  template <>
  struct hash<BilinearGroup::G2>
  {
    size_t operator()(const BilinearGroup::G2 &k) const
    {
      size_t s = k.size();
      std::vector<uint8_t> buf(s);
      k.serialize(buf.data(), s);

      return djb_hash(buf.data(), s);
    }
  };

} // namespace std

std::istream &operator>>(std::istream &is, BilinearGroup::BN &e);
std::istream &operator>>(std::istream &is, BilinearGroup::G1 &e);
std::istream &operator>>(std::istream &is, BilinearGroup::G2 &e);
std::istream &operator>>(std::istream &is, BilinearGroup::GT &e);

std::ostream &operator<<(std::ostream &os, BilinearGroup::BN const &e);
std::ostream &operator<<(std::ostream &os, BilinearGroup::G1 const &e);
std::ostream &operator<<(std::ostream &os, BilinearGroup::G2 const &e);
std::ostream &operator<<(std::ostream &os, BilinearGroup::GT const &e);
