#pragma once
#include "group.h"
#include <assert.h>
#include <iostream>
#include <type_traits>
#include <vector>

namespace BilinearGroup
{
template <typename T> class Matrix
{
public:
  /**
   * Initialize a matrix from another matrix.<br>
   * (Copy constructor)
   *
   * @param[in] mat - The matrix to copy.
   */
  Matrix(const Matrix<T> &mat) : m_rows(mat.m_rows), m_cols(mat.m_cols), m_zero(mat.m_zero), m_data(mat.m_data) {}

  /**
   * Initialize a matrix from a vector containing all data.<br>
   * The matrix dimensions are given and will seperate the vector row wise:<br>
   * vector(row0element0, ..., row0element[cols], ..., row[rows]element0, ..., row[rows]element[cols])<br>
   * The vector has to have size rows*cols.
   *
   * @param[in] rows - The number of rows.
   * @param[in] cols - The number of columns.
   * @param[in] zero - The neutral element for addition.
   * @param[in] values - The vector containing the elements of the matrix.
   */
  Matrix(size_t rows, size_t cols, const T &zero, const std::vector<T> &values)
      : m_rows(rows), m_cols(cols), m_zero(zero)
  {
    assert(values.size() == rows * cols);
    m_data = values;
  }

  /**
   * Initialize a matrix from a row vector.
   *
   * @param[in] zero - The neutral element for addition.
   * @param[in] values - The row vector for the first row of the matrix.
   */
  Matrix(const T &zero, const std::vector<T> &values) : m_rows(1), m_cols(values.size()), m_zero(zero), m_data(values)
  {
  }

  /**
   * Initialize a matrix with an initialization element.
   *
   * @param[in] rows - The number of rows.
   * @param[in] cols - The number of columns.
   * @param[in] zero - The neutral element for addition.
   * @param[in] init_val - The initial value of all elements in the matrix.
   */
  Matrix(size_t rows, size_t cols, const T &zero, const T &init_val)
      : m_rows(rows), m_cols(cols), m_zero(zero), m_data(rows * cols, init_val)
  {
  }

  /**
   * Initialize a matrix.<br>
   * All elements will have the value of the neutral element.
   *
   * @param[in] rows - The number of rows.
   * @param[in] cols - The number of columns.
   * @param[in] zero - The neutral element for addition.
   */
  Matrix(size_t rows, size_t cols, const T &zero) : Matrix(rows, cols, zero, zero) {}

  Matrix(size_t rows, size_t cols) : m_rows(rows), m_cols(cols), m_zero(T::get_infty())
  {
    int size = rows * cols;
    m_data.resize(rows * cols);
    for (int i = 0; i < size; i++)
    {
      m_data[i] = T::rand();
    }
  }

  /**
   * Initialize a new empty 0x0 matrix.
   */
  Matrix()
  {
    m_rows = 0;
    m_cols = 0;
  }

  /**
   * Reset to an empty 0x0 matrix.
   */
  void clear()
  {
    m_rows = 0;
    m_cols = 0;
    m_data.clear();
  }

  /**
   * Copy assignment operator.<br>
   * This matrix will equal the other matrix.
   *
   * @param[in] other - The matrix to copy.
   * @returns This matrix.
   */
  Matrix<T> &operator=(const Matrix<T> &other)
  {
    m_rows = other.m_rows;
    m_cols = other.m_cols;
    m_data = other.m_data;
    m_zero = other.m_zero;

    return *this;
  }

  /**
   * Get the number of rows of the matrix.
   *
   * @returns The row count.
   */
  inline size_t rows() const { return m_rows; }

  /**
   * Get the number of columns of the matrix.
   *
   * @returns The column count.
   */
  inline size_t cols() const { return m_cols; }

  /**
   * Element access operator.
   *
   * @param[in] row - The row of the element.
   * @param[in] col - The column of the element.
   * @returns A reference to the element at (row, col).
   */
  T &operator()(size_t row, size_t col)
  {
    assert(row < rows() && col < cols());
    return m_data.at(col + cols() * row);
  }

  /**
   * Constant element access operator.
   *
   * @param[in] row - The row of the element.
   * @param[in] col - The column of the element.
   * @returns A const reference to the element at (row, col).
   */
  const T &operator()(size_t row, size_t col) const
  {
    assert(row < rows() && col < cols());
    return m_data.at(col + cols() * row);
  }

  /**
   * Sets row x to the values in the vector.<br>
   * The vector must have exactly col() entries.
   *
   * @param[in] row - The row to overwrite.
   * @param[in] values - The new values.
   */
  void set_row(size_t row, const std::vector<T> &values)
  {
    assert(row < rows() && values.size() == cols());
    for (size_t i = 0; i < values.size(); ++i)
    {
      (*this)(row, i) = values.at(i);
    }
  }

  /**
   * Sets row x to the values of a 1xn matrix.<br>
   * The matrix dimension n must equal cols().
   *
   * @param[in] row - The row to overwrite.
   * @param[in] values - The new values.
   */
  void set_row(size_t row, const Matrix<T> &values)
  {
    assert(row < rows() && values.rows() == 1 && values.cols() == cols());
    for (size_t i = 0; i < values.size(); ++i)
    {
      (*this)(row, i) = values(0, i);
    }
  }

  /**
   * Gets all rows concatenated in vector.
   *
   * @returns All elements of the matrix.
   */
  std::vector<T> to_vector() const { return m_data; }

  /**
   * Gets a single row as a 1x[cols()] matrix.
   *
   * @param[in] row - The row to overwrite.
   * @returns The row matrix.
   */
  Matrix<T> get_row(size_t row) const
  {
    Matrix<T> res(1, cols(), m_zero);

    for (size_t i = 0; i < cols(); ++i)
    {
      res(0, i) = (*this)(row, i);
    }

    return res;
  }

  /**
   * Adds a 1xn matrix as a new row.<br>
   * The matrix dimension n must equal cols() or this matrix has to have dimension 0x0.
   * If this is a 0x0 matrix, it will afterwards be a 1xn matrix.
   *
   * @param[in] values - The new row.
   */
  void add_row(const Matrix<T> &values)
  {
    if (m_rows == 0 && m_cols == 0)
    {
      m_cols = values.cols();
      m_zero = values.get_zero();
    }
    /* values.rows() must be 1 because this only adds a 1xn matrix */
    assert(values.rows() == 1 && values.cols() == cols());
    m_rows++;
    for (const auto &v : values.m_data)
    {
      m_data.push_back(v);
    }
  }

  /**
   * Sets column x to the values of a vector.<br>
   * The vector length n must equal rows().
   *
   * @param[in] col - The column to overwrite.
   * @param[in] values - The new values.
   */
  void set_column(size_t col, const std::vector<T> &values)
  {
    assert(col < cols() && values.size() <= rows());
    for (size_t i = 0; i < values.size(); ++i)
    {
      (*this)(i, col) = values.at(i);
    }
  }

  /**
   * Adds another matrix to this matrix and returns the result as a new matrix.<br>
   * Both operands have to have equal dimensions.
   *
   * @param[in] other - The matrix to add.
   * @returns The sum of this and other matrix.
   */
  Matrix<T> operator+(const Matrix<T> &other) const
  {
    assert(rows() == other.rows() && cols() == other.cols());

    Matrix<T> r(rows(), cols(), m_zero);

    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        r(row, col) = (*this)(row, col) + other(row, col);
      }
    }
    return r;
  }

  /**
   * Adds another matrix to this matrix.<br>
   * Both operands have to have equal dimensions.
   *
   * @param[in] other - The matrix to add.
   * @returns This matrix.
   */
  Matrix<T> &operator+=(const Matrix<T> &other)
  {
    assert(rows() == other.rows() && cols() == other.cols());

    for (size_t col = 0; col < cols(); ++col)
    {
      for (size_t row = 0; row < rows(); ++row)
      {
        (*this)(row, col) += other(row, col);
      }
    }
    return *this;
  }

  /**
   * Subtracts another matrix from this matrix and returns the result as a new matrix.<br>
   * Both operands have to have equal dimensions.
   *
   * @param[in] other - The matrix to subtract.
   * @returns The difference of this and other matrix.
   */
  Matrix<T> operator-(const Matrix<T> &other) const
  {
    assert(rows() == other.rows() && cols() == other.cols());

    Matrix<T> r(rows(), cols(), m_zero);

    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        r(row, col) = (*this)(row, col) - other(row, col);
      }
    }
    return r;
  }



  /**
   * Subtracts another matrix from this matrix.<br>
   * Both operands have to have equal dimensions.
   *
   * @param[in] other - The matrix to subtract.
   * @returns This matrix.
   */
  Matrix<T> &operator-=(const Matrix<T> &other)
  {
    assert(rows() == other.rows() && cols() == other.cols());

    for (size_t col = 0; col < cols(); ++col)
    {
      for (size_t row = 0; row < rows(); ++row)
      {
        (*this)(row, col) -= other(row, col);
      }
    }
    return *this;
  }

  /**
   * Multiplies the other matrix with this matrix and returns the result as a new matrix.<br>
   * The columns of this matrix must equal the rows of the other matrix.
   *
   * @param[in] other - The matrix to multiply.
   * @returns The product (this * other).
   */
  template <typename X>
  auto operator*(const Matrix<X> &other) const
      -> Matrix<typename std::conditional<std::is_same<X, BilinearGroup::BN>::value, T, X>::type>
  {
    assert(cols() == other.rows());
    using RType = typename std::conditional<std::is_same<X, BilinearGroup::BN>::value, T, X>::type;
    Matrix<RType> r(rows(), other.cols(), RType::get_infty());

    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < other.cols(); ++col)
      {
        for (size_t i = 0; i < other.rows(); ++i)
        {
          r(row, col) += ((*this)(row, i) * other(i, col));
        }
      }
    }
    return r;
  }

  auto operator*(const Matrix<GT> &other) const
  {
    assert(cols() == other.rows());
    Matrix<GT> r(rows(), other.cols(), GT::get_unity());

    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < other.cols(); ++col)
      {
        for (size_t i = 0; i < other.rows(); ++i)
        {
          r(row, col) += ((*this)(row, i) * other(i, col));
        }
      }
    }
    return r;
  }

  /**
   * Multiplies the other matrix with this matrix and stores the result in this matrix.<br>
   * The columns of this matrix must equal the rows of the other matrix.
   *
   * @param[in] other - The matrix to multiply.
   * @returns The product (this * other).
   */
  template <typename X> Matrix<X> &operator*=(const Matrix<X> &other)
  {
    auto r = ((*this) * other);
    m_data = r.m_data;
    m_cols = r.cols();
    m_rows = r.rows();
    return *this;
  }

  /**
   * Multiplies this matrix with a scalar (element wise) and returns the result as a new matrix.
   *
   * @param[in] scalar - The scalar to multiply.
   * @returns The scaled matrix.
   */
  template <typename X> Matrix<T> operator*(const X &scalar) const
  {
    Matrix<T> r(rows(), cols(), m_zero, m_data);

    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        r(row, col) *= scalar;
      }
    }
    return r;
  }

  /**
   * Multiplies every element of this matrix with a scalar.
   *
   * @param[in] scalar - The scalar to multiply.
   * @returns This matrix.
   */
  template <typename X> Matrix<T> &operator*=(const X &scalar)
  {
    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        (*this)(row, col) *= scalar;
      }
    }
    return *this;
  }

  /**
   * Reduces the matrix with a modulus (element wise) and returns the result as a new matrix.
   *
   * @param[in] mod - The modulus.
   * @returns The reduced matrix.
   */
  template <typename X> Matrix<T> operator%(const X &mod) const
  {
    Matrix<T> r(rows(), cols(), m_zero, m_data);

    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        r(row, col) %= mod;
      }
    }
    return r;
  }

  /**
   * Reduces every element of this matrix with a modulus.
   *
   * @param[in] mod - The modulus.
   * @returns This matrix.
   */
  template <typename X> Matrix<T> &operator%=(const X &mod)
  {
    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        (*this)(row, col) %= mod;
      }
    }
    return *this;
  }

  /**
   * Transpose this matrix.
   *
   * @returns The transposed matrix.
   */
  Matrix<T> transpose() const
  {
    Matrix<T> m(cols(), rows(), m_zero);
    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        m(col, row) = (*this)(row, col);
      }
    }

    return m;
  }

  bool operator==(const Matrix<T> &x) const
  {
    if (m_cols != x.cols() || m_rows != x.rows())
    {
      return false;
    }

    for (size_t i = 0; i < m_data.size(); ++i)
    {
      if (m_data.at(i) != x.m_data.at(i))
      {
        return false;
      }
    }
    return true;
  }

  bool operator!=(const Matrix<T> &x) const { return !(*this == x); }

  void print() const
  {
    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        std::cout << "row: " << row << " col: " << col << "   ";
        (*this)(row, col).print();
      }
      std::cout << std::endl;
    }
  }

    void precompute() const
  {
    for (size_t row = 0; row < rows(); ++row)
    {
      for (size_t col = 0; col < cols(); ++col)
      {
        T val = (*this)(row, col);
        val.precompute();
      }
    }
  }

  /**
   * Get the additive neutral element.
   *
   * @returns The neutral element.
   */
  const T &get_zero() const { return m_zero; }

private:
  size_t m_rows;
  size_t m_cols;
  T m_zero;
  std::vector<T> m_data;
};

template <class T> class 






vectorBG : public std::vector<T>
{
public:
  using std::vector<T>::vector;
  


  // inner product
  template <class R> T operator*(const vectorBG<R> &x) const
  {
    if (x.size() != this->size())
    {
      throw std::invalid_argument("vectors have different size.");
    }

    T res = 0;
    for (size_t i = 0; i < this->size(); ++i)
    {
      res += this->at(i) * x[i];
    }
    return res;
  }

  template <class R> vectorBG<T> operator*(const R &x) const
  {
    vectorBG<T> res;
    res.reserve(x.size());
    for (const auto &v : *this)
    {
      res.push_back(v * x);
    }
    return res;
  }

  vectorBG<T> operator%(const T &x) const
  {
    vectorBG<T> res;
    res.reserve(x.size());
    for (const auto &v : *this)
    {
      res.push_back(v % x);
    }
    return res;
  }

  vectorBG<T> operator+(const vectorBG<T> &x) const
  {
    if (x.size() != this->size())
    {
      throw std::runtime_error("vectors have different size.");
    }

    vectorBG<T> res;
    res.reserve(x.size());
    for (size_t i = 0; i < this->size(); ++i)
    {
      res.push_back(this->at(i) + x.at(i));
    }
    return res;
  }

  vectorBG<T> operator-(const vectorBG<T> &x) const
  {
    if (x.size() != this->size())
    {
      throw std::runtime_error("vectors have different size.");
    }

    vectorBG<T> res;
    res.reserve(x.size());
    for (size_t i = 0; i < this->size(); ++i)
    {
      res.push_back(this->at(i) - x.at(i));
    }
    return res;
  }

  template <class R> void operator*=(const R &x)
  {
    for (size_t i = 0; i < this->size(); ++i)
    {
      (*this)[i] *= x;
    }
  }

  void operator%=(const T &x)
  {
    for (size_t i = 0; i < this->size(); ++i)
    {
      (*this)[i] %= x;
    }
  }

  void operator+=(const vectorBG<T> &x)
  {
    if (x.size() != this->size())
    {
      throw std::runtime_error("vectors have different size.");
    }

    for (size_t i = 0; i < this->size(); ++i)
    {
      (*this)[i] += x.at(i);
    }
  }

  void operator-=(const vectorBG<T> &x)
  {
    if (x.size() != this->size())
    {
      throw std::runtime_error("vectors have different size.");
    }

    for (size_t i = 0; i < this->size(); ++i)
    {
      (*this)[i] -= x.at(i);
    }
  }

  friend std::ostream &operator<<(std::ostream &stream, const vectorBG &x)
  {
    stream << "[";
    if (x.size() > 0)
    {
      stream << x.at(0);
      for (size_t i = 1; i < x.size(); ++i)
      {
        stream << ", " << x.at(i);
      }
    }
    stream << "]";

    return stream;
  }
};

template <class T> Matrix<T> multiply_matrix_with_generator(const Matrix<BN> &matrix)
{
  Matrix<T> result(matrix.rows(), matrix.cols(), T::get_infty());
  for (int i = 0; i < matrix.rows(); i++)
  {
    for (int j = 0; j < matrix.cols(); j++)
    {
      result(i, j) = matrix(i, j) * T::get_gen();
    }
  }
  return result;
}
BN hash_G1_elements_to_BN(const std::vector<G1> &input);
G1 hash_G1_elements_to_G1(const std::vector<G1> &input);


Matrix<GT> calculate_pairing_matrix(const Matrix<G1> &g1_matrix, const Matrix<G2> &g2_matrix);
Matrix<GT> calculate_pairing_matrix_element_wise(const Matrix<G1> &g1_matrix, const G2 &g2_element);
template <typename T> T hash_G1_elements(const std::vector<G1> &input)
{
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
} // namespace BilinearGroup
