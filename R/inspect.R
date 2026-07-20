#' Look under the hood of encrypted objects
#'
#' Nothing about an encrypted object is hidden from its owner: these
#' functions expose exactly what keys and ciphertexts are made of.
#'
#' `chunks()` returns the underlying OpenFHE ciphertexts of a
#' [Ciphertext-class] as a list of single-ciphertext `Ciphertext` objects.
#' A vector of up to [slot_count()] elements is held in one ciphertext, so
#' `chunks()` returns a list of length one; longer vectors spill across
#' several (all fully packed except possibly the last), split in element
#' order.  Each chunk is a normal `Ciphertext` and can be decrypted (or,
#' in later phases, computed with) on its own.
#'
#' `as.character()` renders the raw cryptographic content -- the ring
#' polynomials in OpenFHE's internal RNS (residue number system)
#' representation, one big-integer coefficient per slot per residue tower.
#' It is exact but *large* (easily megabytes for realistic parameters), so
#' nothing prints it by default: `show` methods print compact summaries,
#' and viewing the raw content is an explicit act.  Display with
#' `cat(as.character(x))`.
#'
#' @param x A [Ciphertext-class] for `chunks()`; a `Ciphertext`,
#'   [FHEKeys-class], `FHEPublicKey` or `FHESecretKey` for
#'   `as.character()`.
#' @param ... Unused; for consistency with the base generic.
#'
#' @return `chunks()` returns a list of [Ciphertext-class] objects.
#'   `as.character()` returns a character vector: one element per
#'   underlying ciphertext for a `Ciphertext`, one element for a single
#'   key, and a named length-2 vector (`public_key`, `secret_key`) for an
#'   [FHEKeys-class].
#' @seealso [encrypt()], [keygen()], [slot_count()]
#' @examples
#' ctx <- fhe_context("BFV", mult_depth = 2, security = NA, ring_dim = 1024)
#' keys <- keygen(ctx)
#' ct <- encrypt(1:5, keys)
#'
#' chunks(ct)  # short vector: a single underlying ciphertext
#'
#' # the raw polynomials (truncated here; cat() the full string to see all)
#' substr(as.character(ct)[1], 1, 60)
#' @name openfhe-inspect
NULL

#' @rdname openfhe-inspect
#' @export
setGeneric("chunks", function(x) standardGeneric("chunks"))

#' @rdname openfhe-inspect
#' @export
setMethod("chunks", "Ciphertext", function(x) {
  check_live(x)
  slots <- slot_count(x@context)
  n_ct <- length(x@ptrs)
  lapply(seq_len(n_ct), function(i) {
    len <- if (i < n_ct) slots else x@length - (n_ct - 1L) * slots
    methods::new("Ciphertext", ptrs = x@ptrs[i], context = x@context,
                 length = as.integer(len))
  })
})

#' @rdname openfhe-inspect
#' @export
setMethod("as.character", "Ciphertext", function(x, ...) {
  check_live(x)
  vapply(x@ptrs, ct_text_, character(1))
})

#' @rdname openfhe-inspect
#' @export
setMethod("as.character", "FHEPublicKey", function(x, ...) {
  check_live(x)
  pk_text_(x@ptr)
})

#' @rdname openfhe-inspect
#' @export
setMethod("as.character", "FHESecretKey", function(x, ...) {
  check_live(x)
  sk_text_(x@ptr)
})

#' @rdname openfhe-inspect
#' @export
setMethod("as.character", "FHEKeys", function(x, ...) {
  c(public_key = as.character(x@public_key),
    secret_key = as.character(x@secret_key))
})
