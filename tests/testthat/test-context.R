# Note ring_dim 1024: OpenFHE 1.5.1 rejects the BGV/depth-2/ring-512 corner
# (EstimateLogP failure in hybrid key switching); 1024 works for all schemes.
toy <- function(scheme = "CKKS", ...) {
  fhe_context(scheme, mult_depth = 2, security = NA, ring_dim = 1024, ...)
}

test_that("toy contexts can be created for all three schemes", {
  for (s in c("CKKS", "BFV", "BGV")) {
    ctx <- toy(s)
    expect_s4_class(ctx, "FHEContext")
    expect_identical(scheme(ctx), s)
    expect_identical(ring_dim(ctx), 1024L)
    expect_identical(mult_depth(ctx), 2L)
  }
})

test_that("slot counts follow the scheme packing rules", {
  expect_identical(slot_count(toy("CKKS")), 512L)   # ring_dim / 2
  expect_identical(slot_count(toy("BFV")), 1024L)   # ring_dim
  expect_identical(slot_count(toy("CKKS", batch_size = 8)), 8L)
})

test_that("a standard-security context chooses its own ring dimension", {
  ctx <- fhe_context("CKKS", mult_depth = 1, security = 128)
  expect_gte(ring_dim(ctx), 8192L)
  expect_identical(slot_count(ctx), ring_dim(ctx) %/% 2L)
})

test_that("scheme-specific arguments are rejected for the wrong scheme", {
  expect_error(toy("BFV", scale_bits = 40), class = "openfhe_scheme_error")
  expect_error(toy("BGV", scaling = "fixed"), class = "openfhe_scheme_error")
  expect_error(toy("BFV", bootstrap = TRUE), class = "openfhe_scheme_error")
  expect_error(toy("CKKS", plaintext_modulus = 65537),
               class = "openfhe_scheme_error")
})

test_that("parameter validation raises classed errors", {
  expect_error(fhe_context("CKKS", security = NA),
               class = "openfhe_scheme_error")  # toy needs ring_dim
  expect_error(fhe_context("CKKS", security = 100),
               class = "openfhe_scheme_error")
  expect_error(fhe_context("CKKS", security = NA, ring_dim = 500),
               class = "openfhe_scheme_error")  # not a power of two
  expect_error(fhe_context("CKKS", mult_depth = -1, security = NA,
                           ring_dim = 512),
               class = "openfhe_scheme_error")
  expect_error(toy("CKKS", scale_bits = 60, first_mod_bits = 60),
               class = "openfhe_scheme_error")
  expect_error(toy("CKKS", batch_size = 7),
               class = "openfhe_scheme_error")
})

test_that("native parameter rejections surface as openfhe_scheme_error", {
  # scale_bits far beyond the 60-bit native word limit
  expect_error(toy("CKKS", scale_bits = 90, first_mod_bits = 100),
               class = "openfhe_scheme_error")
})

test_that("context printing is informative", {
  expect_snapshot(show(toy("CKKS")))
  expect_snapshot(show(toy("BFV")))
})

test_that("bootstrap = TRUE enables the FHE feature", {
  ctx <- toy("CKKS", bootstrap = TRUE)
  expect_true("FHE" %in% ctx@features)
  expect_false("FHE" %in% toy("CKKS")@features)
})
