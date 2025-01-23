#include "deserializer.h"

namespace EpGroup
{
  Deserializer::Deserializer(const std::vector<uint8_t> &buffer) : m_buffer(buffer), m_pos(0) {}

  void Deserializer::deserialize(uint32_t &x)
  {
    check();
    x = m_buffer[m_pos++] << 24;
    x |= m_buffer[m_pos++] << 16;
    x |= m_buffer[m_pos++] << 8;
    x |= m_buffer[m_pos++];
  }

  void Deserializer::deserialize(uint8_t &x)
  {
    check();
    x = m_buffer[m_pos++];
  }

  void Deserializer::deserialize(BN &x)
  {
    check();
    m_pos += x.deserialize((uint8_t *)(&m_buffer[m_pos]));
  }

  void Deserializer::deserialize(EP &x)
  {
    check();
    m_pos += x.deserialize((uint8_t *)(&m_buffer[m_pos]));
  }

  Deserializer &Deserializer::operator>>(uint8_t &x)
  {
    check();
    x = m_buffer[m_pos++];
    return *this;
  }

  Deserializer &Deserializer::operator>>(uint32_t &x)
  {
    check();
    x = m_buffer[m_pos++] << 24;
    x |= m_buffer[m_pos++] << 16;
    x |= m_buffer[m_pos++] << 8;
    x |= m_buffer[m_pos++];

    return *this;
  }

  Deserializer &Deserializer::operator>>(BN &x)
  {
    check();
    m_pos += x.deserialize((uint8_t *)(&m_buffer[m_pos]));
    return *this;
  }

  Deserializer &Deserializer::operator>>(EP &x)
  {
    check();
    m_pos += x.deserialize((uint8_t *)(&m_buffer[m_pos]));
    return *this;
  }

  void Deserializer::set_pos(uint32_t pos) { m_pos = pos; }

  uint32_t Deserializer::get_pos() { return m_pos; }

  uint32_t Deserializer::available() { return m_buffer.size() - m_pos; }
  void Deserializer::check()
  {
    if (available() == 0)
    {
      throw std::runtime_error("deserializer is out of data");
    }
  }

} // namespace BilinearGroup
