test_that("chunks() exposes the underlying ciphertexts", {
  ctx <- toy("CKKS")
  keys <- keygen(ctx)
  slots <- slot_count(ctx)

  # short vector: one chunk, decrypting it matches the whole
  ct <- encrypt(c(1.5, -2.5), keys)
  cs <- chunks(ct)
  expect_length(cs, 1L)
  expect_s4_class(cs[[1]], "Ciphertext")
  expect_identical(length(cs[[1]]), 2L)
  expect_equal(decrypt(cs[[1]], keys), c(1.5, -2.5), tolerance = 1e-4)

  # spilled vector: chunk lengths partition the vector in element order
  x <- seq_len(slots + 100) / 7
  cs <- chunks(encrypt(x, keys))
  expect_length(cs, 2L)
  expect_identical(vapply(cs, length, integer(1)), c(slots, 100L))
  expect_equal(decrypt(cs[[1]], keys), x[1:slots], tolerance = 1e-4)
  expect_equal(decrypt(cs[[2]], keys), x[(slots + 1):length(x)],
               tolerance = 1e-4)
})

test_that("as.character() exposes the raw polynomial content", {
  keys <- keygen(toy("BFV"))
  ct <- encrypt(1:5, keys)

  txt <- as.character(ct)
  expect_type(txt, "character")
  expect_length(txt, 1L)
  # a fresh ciphertext is (at least) two ring polynomials of big coefficients
  expect_match(txt, "polynomial 0:")
  expect_match(txt, "polynomial 1:")
  expect_gt(nchar(txt), 1000)

  # one string per underlying ciphertext when spilled
  expect_length(as.character(encrypt(seq_len(2000L), keys)), 2L)

  expect_match(as.character(keys@public_key), "polynomial 0:")
  expect_match(as.character(keys@secret_key), "polynomial 0:")
  both <- as.character(keys)
  expect_named(both, c("public_key", "secret_key"))
  expect_identical(unname(both["secret_key"]),
                   as.character(keys@secret_key))
})
