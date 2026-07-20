test_that("CKKS round trip recovers real values approximately", {
  keys <- keygen(toy("CKKS"))
  x <- c(-2.5, 0, 1.25, 3.75, 1e-3)
  ct <- encrypt(x, keys)
  expect_s4_class(ct, "Ciphertext")
  expect_equal(decrypt(ct, keys), x, tolerance = 1e-4)
})

test_that("BFV and BGV round trips recover integers exactly", {
  x <- c(-32768L, -3L, 0L, 7L, 42L, 32768L)  # extremes of the +/- t/2 range
  for (s in c("BFV", "BGV")) {
    keys <- keygen(toy(s))
    expect_identical(decrypt(encrypt(x, keys), keys), x)
  }
})

test_that("encryption works with the public key alone", {
  keys <- keygen(toy("CKKS"))
  x <- c(1.5, -0.5)
  ct <- encrypt(x, keys@public_key)
  expect_equal(decrypt(ct, keys@secret_key), x, tolerance = 1e-4)
})

test_that("encrypt/decrypt are pipe-friendly", {
  keys <- keygen(toy("BGV"))
  expect_identical(c(5L, -6L) |> encrypt(keys) |> decrypt(keys), c(5L, -6L))
})

test_that("length is preserved, from scalars up to a full ciphertext", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx)
  for (n in c(1L, 2L, 100L, slot_count(ctx))) {
    x <- seq_len(n) / 7
    ct <- encrypt(x, keys)
    expect_identical(length(ct), n)
    expect_equal(decrypt(ct, keys), x, tolerance = 1e-4)
  }
})

test_that("over-long vectors are rejected with the achievable maximum", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx)
  n <- slot_count(ctx)
  expect_error(encrypt(numeric(n + 1), keys),
               class = "openfhe_length_mismatch")
  expect_error(encrypt(numeric(n + 1), keys),
               regexp = sprintf("%d SIMD slots", n))
})

test_that("decrypting with keys from a different context errors", {
  keys1 <- keygen(toy("CKKS"))
  keys2 <- keygen(toy("CKKS"))
  ct <- encrypt(c(1, 2), keys1)
  expect_error(decrypt(ct, keys2), class = "openfhe_context_mismatch")
  expect_error(decrypt(ct, keys2@secret_key),
               class = "openfhe_context_mismatch")
  expect_equal(decrypt(ct, keys1), c(1, 2), tolerance = 1e-4)
})

test_that("BFV/BGV reject non-whole and out-of-range values", {
  keys <- keygen(toy("BFV"))
  expect_error(encrypt(c(1, 2.5), keys), class = "openfhe_scheme_error")
  # |x| > (65537 - 1) / 2
  expect_error(encrypt(32769, keys), class = "openfhe_scheme_error")
})

test_that("logical vectors encrypt as 0/1 with a message", {
  keys <- keygen(toy("BFV"))
  expect_message(ct <- encrypt(c(TRUE, FALSE, TRUE), keys), "0/1")
  expect_identical(decrypt(ct, keys), c(1L, 0L, 1L))
})

test_that("unencryptable inputs raise classed errors", {
  keys <- keygen(toy("CKKS"))
  expect_error(encrypt("a", keys), class = "openfhe_scheme_error")
  expect_error(encrypt(1 + 2i, keys), class = "openfhe_scheme_error")
  expect_error(encrypt(numeric(0), keys), class = "openfhe_scheme_error")
  expect_error(encrypt(c(1, NA), keys), class = "openfhe_scheme_error")
  expect_error(encrypt(c(1, Inf), keys), class = "openfhe_scheme_error")
  expect_error(encrypt(matrix(1:4, 2), keys), class = "openfhe_scheme_error")
})

test_that("ciphertext printing is informative", {
  keys <- keygen(toy("CKKS"))
  expect_snapshot(show(encrypt(c(1.5, 2.5, 3.5), keys)))
})
