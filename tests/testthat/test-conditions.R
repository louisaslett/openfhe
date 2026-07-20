test_that("openfhe conditions carry the expected classes", {
  err <- tryCatch(
    openfhe:::stop_depth_exhausted("depth gone"),
    error = function(e) e
  )
  expect_s3_class(err, "openfhe_depth_exhausted")
  expect_s3_class(err, "openfhe_error")
  expect_s3_class(err, "error")
  expect_match(conditionMessage(err), "depth gone")
})

test_that("specific openfhe conditions can be caught selectively", {
  expect_identical(
    tryCatch(
      openfhe:::stop_length_mismatch("lengths 3 and 5"),
      openfhe_length_mismatch = function(e) "caught-specific",
      openfhe_error = function(e) "caught-general"
    ),
    "caught-specific"
  )
  expect_identical(
    tryCatch(
      openfhe:::stop_scheme_error("not valid for CKKS"),
      openfhe_length_mismatch = function(e) "caught-specific",
      openfhe_error = function(e) "caught-general"
    ),
    "caught-general"
  )
})

test_that("condition constructors attach extra data", {
  err <- tryCatch(
    openfhe:::stop_missing_key("no rotation key for index 3",
                               data = list(index = 3L)),
    error = function(e) e
  )
  expect_s3_class(err, "openfhe_missing_key")
  expect_identical(err$index, 3L)
})

test_that("stale pointer condition points users at save_fhe/load_fhe", {
  err <- tryCatch(openfhe:::stop_stale_pointer(), error = function(e) e)
  expect_s3_class(err, "openfhe_stale_pointer")
  expect_match(conditionMessage(err), "save_fhe")
})
