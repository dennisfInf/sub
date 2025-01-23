#ifndef _DESERIALIZER_H_
#define _DESERIALIZER_H_

#include "matrix.h"
#include <array>

namespace BilinearGroup
{
  class Deserializer
  {
  public:
    Deserializer(const std::vector<uint8_t> &buffer);
    ~Deserializer() = default;

    // reads data from byte position pos and advances pos to the next data blob
    void deserialize(uint8_t &x);
    void deserialize(uint32_t &x);
    void deserialize(BN &x);
    void deserialize(G1 &x);
    void deserialize(G2 &x);
    void deserialize(GT &x);

    template <typename T>
    Deserializer &operator>>(T &x)
    {
      check();
      m_pos += x.deserialize((uint8_t *)(&m_buffer[m_pos]));
      return *this;
    }
    Deserializer &operator>>(uint8_t &x);
    Deserializer &operator>>(uint32_t &x);
    Deserializer &operator>>(BN &x);
    Deserializer &operator>>(G1 &x);
    Deserializer &operator>>(G2 &x);
    Deserializer &operator>>(GT &x);

    void set_pos(uint32_t pos);
    uint32_t get_pos();
    uint32_t available();

    template <class T>
    Deserializer &operator>>(std::vector<T> &vec)
    {
      uint32_t num_elements;
      *this >> num_elements;
      vec.clear();
      vec.reserve(num_elements);
      for (uint32_t i = 0; i < num_elements; ++i)
      {
        T x;
        *this >> x;
        vec.push_back(x);
      }
      return *this;
    }

    template <class T>
    void deserialize(std::vector<T> &x)
    {
      size_t size = m_buffer[m_pos++];
      x.clear();
      x.reserve(size);
      for (size_t i = 0; i < size; ++i)
      {
        T val;
        deserialize(val);
        x.push_back(val);
      }
    }

    template <class T>
    void deserialize(BilinearGroup::vectorBG<T> &x)
    {
      size_t size = m_buffer[m_pos++];
      x.clear();
      x.reserve(size);
      for (size_t i = 0; i < size; ++i)
      {
        T val;
        deserialize(val);
        x.push_back(val);
      }
    }

    Deserializer &operator>>(std::vector<uint8_t> &x)
    {
      uint32_t size;
      deserialize(size);
      x.clear();
      x.reserve(size);
      for (size_t i = 0; i < size; ++i)
      {
        x.push_back(m_buffer[m_pos++]);
      }
      return *this;
    }

    template <class T, size_t size>
    void deserialize(std::array<T, size> &a)
    {
      for (size_t i = 0; i < size; ++i)
      {
        T val;
        deserialize(val);
        a[i] = val;
      }
    }

    template <class T>
    void deserialize(Matrix<T> &x)
    {
      size_t r = m_buffer[m_pos++];
      size_t c = m_buffer[m_pos++];
      std::vector<T> vec;
      for (size_t i = 0; i < r * c; ++i)
      {
        T val;
        deserialize(val);
        vec.push_back(val);
      }
      x = Matrix<T>(r, c, T::get_infty(), vec);
    }

    template <class T>
    void deserialize(T &x) { x.deserialize_from(*this); }

  private:
    void check();
    const std::vector<uint8_t> &m_buffer;
    uint32_t m_pos;
  };
} // namespace BilinearGroup
#endif
