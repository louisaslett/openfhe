#' Create a homomorphic encryption context
#'
#' A context fixes the encryption scheme and all of its parameters; keys,
#' plaintext encodings and ciphertexts all live relative to one context.
#' Sensible defaults are chosen so that `fhe_context("CKKS")` just works;
#' the parameters below are the ones users typically need to touch.
#'
#' @section Choosing a scheme:
#' * `"CKKS"` computes on **real numbers, approximately** -- the workhorse
#'   for statistics and machine learning.
#' * `"BFV"` and `"BGV"` compute on **integers, exactly**, modulo
#'   `plaintext_modulus`.
#'
#' @section Security:
#' `security = 128` (the default), `192` or `256` selects the corresponding
#' HomomorphicEncryption.org standard parameter sets; OpenFHE then chooses a
#' ring dimension automatically (unless `ring_dim` is forced).
#' `security = NA` disables the standard entirely and is **only for toy
#' examples and tests**: it allows tiny, fast, INSECURE parameters and then
#' requires `ring_dim` to be given explicitly.  Never use `security = NA`
#' with real data.
#'
#' @param scheme `"CKKS"` (approximate reals, the default), `"BFV"` or
#'   `"BGV"` (exact modular integers).
#' @param mult_depth Multiplicative depth budget: the maximum number of
#'   sequential ciphertext multiplications that can be applied before
#'   decryption fails (or bootstrapping is needed).  Larger budgets cost
#'   memory and time.
#' @param security Target security level in bits: `128`, `192`, `256`, or
#'   `NA` for unvalidated toy parameters (see Security section).
#' @param ring_dim Ring dimension, a power of two.  Leave `NULL` (default)
#'   to let OpenFHE choose the smallest secure dimension; must be supplied
#'   when `security = NA`.
#' @param batch_size Number of SIMD slots to encode per ciphertext.  Leave
#'   `NULL` for the maximum (`ring_dim/2` for CKKS, `ring_dim` for
#'   BFV/BGV).
#' @param scale_bits CKKS only: bits of precision of the encoding scaling
#'   factor (default 50).  More bits, more precision, bigger parameters.
#' @param first_mod_bits CKKS only: bits of the first modulus (default 60);
#'   must exceed `scale_bits`.
#' @param scaling CKKS only: rescaling management.  `"auto"` (default,
#'   FLEXIBLEAUTO) and `"auto-ext"` (FLEXIBLEAUTOEXT) rescale automatically;
#'   `"fixed"` (FIXEDMANUAL) is for experts who rescale by hand.
#' @param bootstrap CKKS only: set `TRUE` if you intend to bootstrap
#'   ciphertexts created under this context (enables the FHE feature set;
#'   bootstrapping keys are generated at key-generation time).
#' @param plaintext_modulus BFV/BGV only: the integer plaintext modulus
#'   \eqn{t}; all arithmetic is exact modulo \eqn{t}.  The default 65537 is
#'   prime and supports SIMD packing for every `ring_dim` up to 32768.
#'
#' @return An [FHEContext-class] object.
#' @seealso [scheme()], [ring_dim()], [slot_count()], [mult_depth()]
#' @examples
#' # Toy CKKS context: tiny, fast and INSECURE -- for examples only
#' ctx <- fhe_context("CKKS", mult_depth = 2, security = NA, ring_dim = 512)
#' ctx
#'
#' # Toy BFV context for exact integer arithmetic
#' fhe_context("BFV", mult_depth = 2, security = NA, ring_dim = 512)
#' @export
fhe_context <- function(scheme = c("CKKS", "BFV", "BGV"),
                        mult_depth = 10,
                        security = 128,
                        ring_dim = NULL,
                        batch_size = NULL,
                        scale_bits = 50,
                        first_mod_bits = 60,
                        scaling = c("auto", "auto-ext", "fixed"),
                        bootstrap = FALSE,
                        plaintext_modulus = 65537) {
  scheme <- match.arg(scheme)

  # scheme-specific arguments must not be supplied to the wrong scheme
  if (scheme != "CKKS") {
    given <- c(
      scale_bits = !missing(scale_bits),
      first_mod_bits = !missing(first_mod_bits),
      scaling = !missing(scaling),
      bootstrap = !missing(bootstrap)
    )
    if (any(given)) {
      stop_scheme_error(sprintf(
        "argument%s %s appl%s to the CKKS scheme only, not %s",
        if (sum(given) > 1) "s" else "",
        paste(sQuote(names(given)[given]), collapse = ", "),
        if (sum(given) > 1) "y" else "ies", scheme
      ))
    }
  } else if (!missing(plaintext_modulus)) {
    stop_scheme_error(paste0(
      "'plaintext_modulus' applies to the exact-integer schemes (BFV/BGV) ",
      "only; CKKS encrypts real numbers and has no plaintext modulus"
    ))
  }
  scaling <- match.arg(scaling)

  check_count <- function(x, nm, min = 1) {
    if (!(is.numeric(x) && length(x) == 1 && !is.na(x) &&
            x == trunc(x) && x >= min)) {
      stop_scheme_error(sprintf(
        "'%s' must be a single integer >= %d", nm, min
      ))
    }
    as.integer(x)
  }

  mult_depth <- check_count(mult_depth, "mult_depth", min = 0)
  if (!(length(security) == 1 &&
          (is.na(security) || security %in% c(128, 192, 256)))) {
    stop_scheme_error("'security' must be 128, 192, 256 or NA (toy parameters)")
  }
  security <- if (is.na(security)) NA_integer_ else as.integer(security)

  if (!is.null(ring_dim)) {
    ring_dim <- check_count(ring_dim, "ring_dim", min = 16)
    if (bitwAnd(ring_dim, ring_dim - 1L) != 0L) {
      stop_scheme_error("'ring_dim' must be a power of two")
    }
  } else if (is.na(security)) {
    stop_scheme_error(paste0(
      "when security = NA (toy parameters) 'ring_dim' must be given ",
      "explicitly, e.g. ring_dim = 512"
    ))
  }
  if (!is.null(batch_size)) {
    batch_size <- check_count(batch_size, "batch_size")
    if (bitwAnd(batch_size, batch_size - 1L) != 0L) {
      stop_scheme_error("'batch_size' must be a power of two")
    }
  }
  scale_bits <- check_count(scale_bits, "scale_bits")
  first_mod_bits <- check_count(first_mod_bits, "first_mod_bits")
  if (scheme == "CKKS" && first_mod_bits <= scale_bits) {
    stop_scheme_error("'first_mod_bits' must exceed 'scale_bits'")
  }
  plaintext_modulus <- check_count(plaintext_modulus, "plaintext_modulus",
                                   min = 2)

  params <- list(
    scheme = scheme,
    mult_depth = mult_depth,
    security = security,
    ring_dim = ring_dim,
    batch_size = batch_size,
    scale_bits = if (scheme == "CKKS") scale_bits else NULL,
    first_mod_bits = if (scheme == "CKKS") first_mod_bits else NULL,
    scaling = if (scheme == "CKKS") scaling else NULL,
    bootstrap = if (scheme == "CKKS") isTRUE(bootstrap) else FALSE,
    plaintext_modulus = if (scheme != "CKKS") plaintext_modulus else NULL
  )

  opts <- list(
    mult_depth = mult_depth,
    security_bits = if (is.na(security)) 0L else security,
    ring_dim = if (is.null(ring_dim)) 0L else ring_dim,
    batch_size = if (is.null(batch_size)) 0L else batch_size,
    scale_bits = scale_bits,
    first_mod_bits = first_mod_bits,
    scaling = scaling,
    bootstrap = params$bootstrap,
    plaintext_modulus = as.double(plaintext_modulus)
  )

  ptr <- tryCatch(
    ctx_new_(scheme, opts),
    error = function(e) {
      stop_scheme_error(
        paste0("OpenFHE rejected these parameters: ", conditionMessage(e)),
        call = sys.call(-4)
      )
    }
  )

  info <- ctx_info_(ptr)
  cache <- new.env(parent = emptyenv())
  cache$ring_dim <- info$ring_dim
  cache$towers <- info$towers
  cache$slots <- if (info$batch_size > 0) {
    info$batch_size
  } else if (scheme == "CKKS") {
    info$ring_dim %/% 2L
  } else {
    info$ring_dim
  }

  features <- c("PKE", "KEYSWITCH", "LEVELEDSHE", "ADVANCEDSHE",
                if (params$bootstrap) "FHE")

  methods::new("FHEContext",
    ptr = ptr, scheme = scheme, params = params,
    features = features, cache = cache
  )
}

#' Inspect a homomorphic encryption context
#'
#' Accessors for the basic facts of an [FHEContext-class]: which scheme it
#' uses, its ring dimension, how many SIMD slots a single ciphertext packs,
#' and its multiplicative depth budget.
#'
#' @param x An [FHEContext-class] object.
#' @return `scheme()` returns `"CKKS"`, `"BFV"` or `"BGV"`; the others
#'   return a single integer.
#' @examples
#' ctx <- fhe_context("CKKS", mult_depth = 2, security = NA, ring_dim = 512)
#' scheme(ctx)
#' ring_dim(ctx)
#' slot_count(ctx)
#' mult_depth(ctx)
#' @name fhe-introspection
NULL

#' @rdname fhe-introspection
#' @export
setGeneric("scheme", function(x) standardGeneric("scheme"))

#' @rdname fhe-introspection
#' @export
setGeneric("ring_dim", function(x) standardGeneric("ring_dim"))

#' @rdname fhe-introspection
#' @export
setGeneric("slot_count", function(x) standardGeneric("slot_count"))

#' @rdname fhe-introspection
#' @export
setGeneric("mult_depth", function(x) standardGeneric("mult_depth"))

#' @rdname fhe-introspection
#' @export
setMethod("scheme", "FHEContext", function(x) x@scheme)

#' @rdname fhe-introspection
#' @export
setMethod("ring_dim", "FHEContext", function(x) x@cache$ring_dim)

#' @rdname fhe-introspection
#' @export
setMethod("slot_count", "FHEContext", function(x) x@cache$slots)

#' @rdname fhe-introspection
#' @export
setMethod("mult_depth", "FHEContext", function(x) x@params$mult_depth)
