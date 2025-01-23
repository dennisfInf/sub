#include "matrix.h"

namespace BilinearGroup
{

// Calculating the pairing of two matrices is done exactly like matrix multiplication, but instead the pairing operator is used.
Matrix<GT> calculate_pairing_matrix(const Matrix<G1> &g1_matrix, const Matrix<G2> &g2_matrix)
{
  //Checks if cols of the first matrix matches the rows of the second matrix (required by matrix multiplication)
  assert(g1_matrix.cols() == g2_matrix.rows());
  //creates a matrix for the result
  Matrix<GT> r(g1_matrix.rows(), g2_matrix.cols(), GT::get_unity());

  //Iterates over the rows of g1
  for (size_t row = 0; row < g1_matrix.rows(); ++row)
  {
    //Iterates over the cols of g2
    for (size_t col = 0; col < g2_matrix.cols(); ++col)
    {
      //Iterates over the elements in the row of g1 and the col of g2
      for (size_t i = 0; i < g2_matrix.rows(); ++i)
      {
        r(row, col) += (GT::map(g1_matrix(row, i), g2_matrix(i, col)));
      }
    }
  }
  return r;
}

Matrix<GT> calculate_pairing_matrix_element_wise(const Matrix<G1> &g1_matrix, const G2 &g2_element)
{
  std::vector<std::future<void>> futures;
  //pairs every element of the matrix with the g2 element
  Matrix<GT> r(g1_matrix.rows(), g1_matrix.cols(), GT::get_unity());

  for (size_t row = 0; row < g1_matrix.rows(); ++row)
  {
    for (size_t col = 0; col < g1_matrix.cols(); ++col)
    {
      // futures.push_back(BilinearGroup::pool.push([&res = r(row, col), &g1_elem = g1_matrix(row, col),
      // &g2_element](int) {}));

      r(row, col) = (GT::map(g1_matrix(row, col), g2_element));
    }
  }
  return r;
}

} // namespace BilinearGroup