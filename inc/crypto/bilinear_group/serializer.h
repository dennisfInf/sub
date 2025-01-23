#ifndef _SERIALIZER_H_
#define _SERIALIZER_H_

#include "matrix.h"
#include <array>

namespace BilinearGroup
{
  class Serializer
  {
  public:
    Serializer(std::vector<uint8_t> &buffer, bool append = false);
    ~Serializer() = default;

    // appends data to the end of the buffer
    Serializer &operator<<(uint8_t x);
    Serializer &operator<<(uint32_t x);
    Serializer &operator<<(const BN &x);
    Serializer &operator<<(const G1 &x);
    Serializer &operator<<(const G2 &x);
    Serializer &operator<<(const GT &x);

    template <class T>
    Serializer &operator<<(const std::vector<T> &vec)
    {
      *this << (uint32_t)vec.size();
      for (const auto &x : vec)
        *this << x;
      return *this;
    }
    Serializer &operator<<(const std::vector<uint8_t> &x)
    {
      uint32_t size = x.size();
      serialize(size);
      for (const auto &e : x)
      {
        m_buffer.push_back(e);
      }
      return *this;
    }
    template <class T>
    Serializer &operator<<(const T &x)
    {
      uint8_t tmp[x.size()];
      uint32_t length = x.serialize(tmp, x.size());
      m_buffer.insert(m_buffer.end(), tmp, tmp + length);

      return *this;
    }

    // legacy serializer
    void serialize(uint8_t x);
    void serialize(uint32_t x);
    void serialize(const BN &x);
    void serialize(const G1 &x);
    void serialize(const G2 &x);
    void serialize(const GT &x);
    template <class T>
    void serialize(const T &x) { x.serialize_to(*this); }

    template <class T, size_t size>
    void serialize(const std::array<T, size> &a)
    {
      for (const auto &val : a)
      {
        serialize(val);
      }
    }

    template <class T>
    void serialize(const std::vector<T> &v)
    {
      m_buffer.push_back(v.size());
      for (const auto &val : v)
      {
        serialize(val);
      }
    }

    template <class T>
    void serialize(const BilinearGroup::vectorBG<T> &v)
    {
      m_buffer.push_back(v.size());
      for (const auto &val : v)
      {
        serialize(val);
      }
    }

    template <class T>
    void serialize(const Matrix<T> &m)
    {
      m_buffer.push_back(m.rows());
      m_buffer.push_back(m.cols());
      for (const auto &val : m.to_vector())
      {
        serialize(val);
      }
    }

  private:
    std::vector<uint8_t> &m_buffer;
  };
} // namespace BilinearGroup
#endif
