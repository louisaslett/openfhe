#' Generate encryption keys for a context
#'
#' `keygen()` generates a public/secret key pair for an [FHEContext-class],
#' together with the evaluation keys homomorphic computation needs:
#'
#' * a **relinearisation key** is always generated -- every ciphertext
#'   multiplication needs one, and generating it up front avoids confusing
#'   failures later;
#' * **sum keys** (`sum = TRUE`, the default) enable `sum()`, `mean()` and
#'   inner products -- core operations for statistical work; opt out with
#'   `sum = FALSE` if you will never reduce across slots;
#' * **rotation keys** are only generated on request (see `rotations`),
#'   because each index costs key material.
#'
#' Evaluation keys are attached to the context (as OpenFHE does natively),
#' so they are available to every ciphertext under that context; the
#' returned [FHEKeys-class] object holds the key pair itself.
#' `rotation_keys()` adds rotation keys for further indices to an existing
#' key set at any later point.
#'
#' @param ctx An [FHEContext-class] created by [fhe_context()].
#' @param rotations Rotation indices to generate keys for: an integer
#'   vector of non-zero shifts (positive = left, negative = right), or
#'   `"power2"` for \eqn{\pm 1, \pm 2, \pm 4, \ldots} up to half the slot
#'   count -- enough to compose any rotation, but note this generates
#'   \eqn{2 \log_2(\mathrm{slots})} keys, which takes time and memory at
#'   realistic parameter sizes.  `NULL` (default) generates none; they can
#'   be added later with `rotation_keys()`.
#' @param sum Generate the sum (automorphism) keys needed by `sum()`,
#'   `mean()` and inner products?  Default `TRUE`.
#' @param keys An [FHEKeys-class] object returned by `keygen()`.
#' @param indices As `rotations` above.
#'
#' @return `keygen()` returns an [FHEKeys-class] object.
#'   `rotation_keys()` returns `keys` invisibly, after attaching the new
#'   rotation keys to the context.
#' @seealso [encrypt()], [decrypt()], [fhe_context()]
#' @examples
#' ctx <- fhe_context("CKKS", mult_depth = 2, security = NA, ring_dim = 1024)
#' keys <- keygen(ctx)
#' keys
#'
#' # rotation keys for specific shifts, added after the fact
#' rotation_keys(keys, c(1, -1))
#' @export
keygen <- function(ctx, rotations = NULL, sum = TRUE) {
  if (!methods::is(ctx, "FHEContext")) {
    stop_scheme_error("'ctx' must be an FHEContext created by fhe_context()")
  }
  check_live(ctx)
  if (!(is.logical(sum) && length(sum) == 1 && !is.na(sum))) {
    stop_scheme_error("'sum' must be TRUE or FALSE")
  }

  kp <- keygen_(ctx@ptr, sum)
  keys <- methods::new(
    "FHEKeys",
    public_key = methods::new("FHEPublicKey", ptr = kp$pk, context = ctx),
    secret_key = methods::new("FHESecretKey", ptr = kp$sk, context = ctx),
    context = ctx
  )

  ctx@cache$mult_key <- TRUE
  ctx@cache$sum_keys <- sum
  ctx@cache$rotations <- integer(0)
  if (!is.null(rotations)) {
    rotation_keys(keys, rotations)
  }
  keys
}

#' @rdname keygen
#' @export
rotation_keys <- function(keys, indices) {
  if (!methods::is(keys, "FHEKeys")) {
    stop_scheme_error("'keys' must be an FHEKeys object returned by keygen()")
  }
  ctx <- keys@context
  check_live(ctx)
  check_live(keys@secret_key)

  slots <- slot_count(ctx)
  if (identical(indices, "power2")) {
    pow <- 2^seq(0, log2(slots) - 1)
    indices <- c(pow, -pow)
  }
  if (!(is.numeric(indices) && length(indices) > 0 && !anyNA(indices) &&
          all(indices == trunc(indices)))) {
    stop_scheme_error(
      "rotation indices must be non-zero integers, or the string \"power2\""
    )
  }
  indices <- unique(as.integer(indices))
  if (any(indices == 0L)) {
    stop_scheme_error("rotation by 0 is the identity; indices must be non-zero")
  }
  if (any(abs(indices) >= slots)) {
    stop_scheme_error(sprintf(
      "rotation indices must be smaller in magnitude than the slot count (%d)",
      slots
    ))
  }

  rot_keygen_(ctx@ptr, keys@secret_key@ptr, indices)
  ctx@cache$rotations <- sort(union(ctx@cache$rotations, indices))
  invisible(keys)
}
