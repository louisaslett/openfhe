test_that("bundled OpenFHE library reports its version", {
  expect_identical(openfhe:::openfhe_version_(), "1.5.1")
})

test_that("C++-side CKKS encrypt/compute/decrypt round trip works", {
  err <- openfhe:::openfhe_selftest_()
  expect_true(is.finite(err))
  expect_lt(err, 1e-3)
})
