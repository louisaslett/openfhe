test_that("keygen returns a key set bound to its context", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx)
  expect_s4_class(keys, "FHEKeys")
  expect_s4_class(keys@public_key, "FHEPublicKey")
  expect_s4_class(keys@secret_key, "FHESecretKey")
  expect_identical(keys@context, ctx)
  expect_identical(keys@public_key@context, ctx)
})

test_that("key generation records the evaluation-key state on the context", {
  ctx <- toy("BFV")
  keygen(ctx)
  expect_true(ctx@cache$mult_key)
  expect_true(ctx@cache$sum_keys)
  expect_identical(ctx@cache$rotations, integer(0))

  ctx2 <- toy("BFV")
  keygen(ctx2, sum = FALSE)
  expect_false(ctx2@cache$sum_keys)
})

test_that("rotation keys can be requested at keygen or added later", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx, rotations = c(1, -1))
  expect_identical(ctx@cache$rotations, c(-1L, 1L))

  rotation_keys(keys, c(2, -1))  # -1 already present; union, not duplicate
  expect_identical(ctx@cache$rotations, c(-1L, 1L, 2L))
})

test_that("rotations = \"power2\" covers +/- powers of two below the slot count", {
  ctx <- toy("CKKS", batch_size = 8)
  keygen(ctx, rotations = "power2")
  expect_identical(ctx@cache$rotations, c(-4L, -2L, -1L, 1L, 2L, 4L))
})

test_that("invalid keygen and rotation arguments raise classed errors", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx)
  expect_error(keygen("not a context"), class = "openfhe_scheme_error")
  expect_error(keygen(ctx, sum = NA), class = "openfhe_scheme_error")
  expect_error(rotation_keys("nope", 1), class = "openfhe_scheme_error")
  expect_error(rotation_keys(keys, 0), class = "openfhe_scheme_error")
  expect_error(rotation_keys(keys, 1.5), class = "openfhe_scheme_error")
  expect_error(rotation_keys(keys, integer(0)), class = "openfhe_scheme_error")
  expect_error(rotation_keys(keys, slot_count(ctx)),
               class = "openfhe_scheme_error")
})

test_that("key printing is informative", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx, rotations = c(1, -1))
  expect_snapshot(show(keys))
  expect_snapshot(show(keys@public_key))
  expect_snapshot(show(keys@secret_key))
})
