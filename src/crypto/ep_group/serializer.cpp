#include "serializer.h"
extern "C"
{
#include "relic.h"
}

namespace EpGroup
{

  Serializer::Serializer(std::vector<uint8_t> &buffer, bool append) : m_buffer(buffer)
  {
    if (!append)
      m_buffer.clear();
  }

  Serializer &Serializer::operator<<(uint8_t x)
  {
    m_buffer.push_back(x);

    return *this;
  }

  Serializer &Serializer::operator<<(uint32_t x)
  {
    m_buffer.push_back((x >> 24) & 0xFF);
    m_buffer.push_back((x >> 16) & 0xFF);
    m_buffer.push_back((x >> 8) & 0xFF);
    m_buffer.push_back(x & 0xFF);

    return *this;
  }

  Serializer &Serializer::operator<<(const BN &x)
  {
    uint8_t tmp[x.size()];
    uint32_t length = x.serialize(tmp, x.size());
    m_buffer.insert(m_buffer.end(), tmp, tmp + length);

    return *this;
  }

  Serializer &Serializer::operator<<(const EP &x)
  {
    uint8_t tmp[x.size()];
    uint32_t length = x.serialize(tmp, x.size());
    m_buffer.insert(m_buffer.end(), tmp, tmp + length);

    return *this;
  }

  // Legacy Code below
  void Serializer::serialize(uint8_t x) { m_buffer.push_back(x); }

  void Serializer::serialize(uint32_t x)
  {
    m_buffer.push_back((x >> 24) & 0xFF);
    m_buffer.push_back((x >> 16) & 0xFF);
    m_buffer.push_back((x >> 8) & 0xFF);
    m_buffer.push_back(x & 0xFF);
  }

  void Serializer::serialize(const BN &x)
  {
    uint32_t size = x.size();
    uint8_t tmp[size];
    uint32_t length = x.serialize(tmp, size);
    m_buffer.insert(m_buffer.end(), tmp, tmp + length);
  }

  void Serializer::serialize(const EP &x)
  {
    uint8_t tmp[RLC_FP_BYTES + 1];
    uint32_t length = x.serialize(tmp, RLC_FP_BYTES + 1);
    m_buffer.insert(m_buffer.end(), tmp, tmp + length);
  }

} // namespace BilinearGroup
