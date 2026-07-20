#' Encrypt and decrypt vectors
#'
#' `encrypt()` turns an R vector into a [Ciphertext-class]: all elements
#' are packed into the SIMD slots of a single OpenFHE ciphertext, so a
#' vector of up to [slot_count()] elements is one encrypted object.
#' `decrypt()` recovers the plaintext vector, at its original length.
#' Both are data-first, so they read naturally in a pipe:
#' `x |> encrypt(keys) |> decrypt(keys)`.
#'
#' @section Scheme-aware encoding:
#' * **CKKS** encrypts real numbers *approximately*: `decrypt()` returns
#'   values close to, but not exactly equal to, the inputs (typically to
#'   many decimal places; see `scale_bits` in [fhe_context()]).
#' * **BFV/BGV** encrypt integers *exactly*, modulo the context's
#'   `plaintext_modulus`.  Values must be whole numbers with magnitude at
#'   most `(plaintext_modulus - 1) / 2`; anything else is an error --
#'   use CKKS for real-valued data.
#' * **Logical** vectors are encrypted as 0/1 (with a message);
#'   complex and character vectors cannot be encrypted.
#'
#' Encryption needs only the public key: `encrypt(x, keys)` and
#' `encrypt(x, keys@public_key)` are equivalent, so a data owner can
#' encrypt against a public key received from elsewhere.  Decryption
#' requires the secret key.
#'
#' @param x The vector to encrypt: numeric for CKKS; whole-valued numeric,
#'   integer or logical for any scheme.  At most [slot_count()] elements
#'   (a context-level limit: raise `ring_dim`/`batch_size`, or split the
#'   data, to fit more).
#' @param keys For `encrypt()` an [FHEKeys-class] or `FHEPublicKey`;
#'   for `decrypt()` an [FHEKeys-class] or `FHESecretKey`.
#' @param ct A [Ciphertext-class] to decrypt.
#' @param ... Unused; reserved for future methods.
#'
#' @return `encrypt()` returns a [Ciphertext-class].  `decrypt()` returns
#'   a numeric vector (CKKS; approximate) or an integer vector (BFV/BGV;
#'   exact, or numeric if any value exceeds R's integer range), of the
#'   same length as the originally encrypted vector.
#' @seealso [keygen()], [fhe_context()]
#' @examples
#' ctx <- fhe_context("CKKS", mult_depth = 2, security = NA, ring_dim = 1024)
#' keys <- keygen(ctx)
#' ct <- encrypt(c(1.5, -2.25, 3), keys)
#' ct
#' decrypt(ct, keys)
#'
#' # exact integer arithmetic under BFV
#' ctx <- fhe_context("BFV", mult_depth = 2, security = NA, ring_dim = 1024)
#' keys <- keygen(ctx)
#' decrypt(encrypt(c(-3L, 0L, 42L), keys), keys)
#' @export
setGeneric("encrypt", function(x, keys, ...) standardGeneric("encrypt"))

#' @rdname encrypt
#' @export
setGeneric("decrypt", function(ct, keys, ...) standardGeneric("decrypt"))

#' @rdname encrypt
#' @export
setMethod("encrypt", signature(x = "ANY", keys = "FHEKeys"),
  function(x, keys, ...) {
    encrypt(x, keys@public_key, ...)
  }
)

#' @rdname encrypt
#' @export
setMethod("encrypt", signature(x = "ANY", keys = "FHEPublicKey"),
  function(x, keys, ...) {
    ctx <- keys@context
    check_live(ctx)
    check_live(keys)

    if (is.matrix(x)) {
      stop_scheme_error(
        "matrix encryption (CipherMatrix) is not implemented yet"
      )
    }
    if (is.logical(x)) {
      message("encrypting logical vector as 0/1")
      x <- as.integer(x)
    }
    if (!is.numeric(x)) {
      stop_scheme_error(sprintf(
        paste0("cannot encrypt a %s vector; only numeric, integer and ",
               "logical data can be encrypted"),
        class(x)[1]
      ))
    }
    if (length(x) == 0) {
      stop_scheme_error("cannot encrypt a zero-length vector")
    }
    if (any(!is.finite(x))) {
      stop_scheme_error(
        "cannot encrypt missing or non-finite values (NA, NaN, Inf)"
      )
    }
    slots <- slot_count(ctx)
    if (length(x) > slots) {
      stop_length_mismatch(sprintf(
        paste0(
          "vector of length %d does not fit the %d SIMD slots of this %s ",
          "context; increase ring_dim (or batch_size), or split the data"
        ),
        length(x), slots, ctx@scheme
      ))
    }

    x <- as.double(x)
    ptr <- if (ctx@scheme == "CKKS") {
      enc_real_(ctx@ptr, keys@ptr, x)
    } else {
      if (any(x != trunc(x))) {
        stop_scheme_error(sprintf(
          paste0(
            "%s encrypts integers exactly; the data contain non-whole ",
            "numbers -- use a CKKS context for real-valued data"
          ),
          ctx@scheme
        ))
      }
      max_abs <- (ctx@params$plaintext_modulus - 1) / 2
      if (any(abs(x) > max_abs)) {
        stop_scheme_error(sprintf(
          paste0(
            "values must have magnitude at most (plaintext_modulus - 1)/2 ",
            "= %.0f under this %s context; increase plaintext_modulus"
          ),
          max_abs, ctx@scheme
        ))
      }
      enc_int_(ctx@ptr, keys@ptr, x)
    }

    methods::new("Ciphertext", ptr = ptr, context = ctx,
                 length = length(x))
  }
)

#' @rdname encrypt
#' @export
setMethod("decrypt", signature(ct = "Ciphertext", keys = "FHEKeys"),
  function(ct, keys, ...) {
    decrypt(ct, keys@secret_key, ...)
  }
)

#' @rdname encrypt
#' @export
setMethod("decrypt", signature(ct = "Ciphertext", keys = "FHESecretKey"),
  function(ct, keys, ...) {
    ctx <- ct@context
    check_live(ctx)
    check_live(ct)
    check_live(keys)
    if (!identical(ctx@ptr, keys@context@ptr)) {
      stop_context_mismatch(paste0(
        "this ciphertext was encrypted under a different context than the ",
        "keys; encrypt, compute and decrypt must all use one context"
      ))
    }

    if (ctx@scheme == "CKKS") {
      dec_real_(ctx@ptr, keys@ptr, ct@ptr, ct@length)
    } else {
      v <- dec_int_(ctx@ptr, keys@ptr, ct@ptr, ct@length)
      if (all(abs(v) <= .Machine$integer.max)) as.integer(v) else v
    }
  }
)
