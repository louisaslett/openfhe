# Classed error conditions used throughout the package.
#
# Every error signalled by openfhe carries the class "openfhe_error" plus a
# more specific subclass, so callers can handle particular failure modes:
#
#   tryCatch(ct1 * ct2,
#            openfhe_depth_exhausted = function(e) bootstrap_and_retry())
#
# Subclasses:
#   openfhe_depth_exhausted  multiplicative depth budget used up
#   openfhe_length_mismatch  non-conformable operands (no silent recycling)
#   openfhe_missing_key      required evaluation key not generated
#   openfhe_stale_pointer    external pointer from a previous R session
#   openfhe_scheme_error     operation or parameter invalid for the scheme
#   openfhe_context_mismatch objects from different contexts combined
#
# All constructors are internal.

stop_openfhe <- function(subclass, message, call = sys.call(-1), data = list()) {
  cnd <- structure(
    class = c(subclass, "openfhe_error", "error", "condition"),
    c(list(message = message, call = call), data)
  )
  stop(cnd)
}

stop_depth_exhausted <- function(message, call = sys.call(-1), data = list()) {
  stop_openfhe("openfhe_depth_exhausted", message, call, data)
}

stop_length_mismatch <- function(message, call = sys.call(-1), data = list()) {
  stop_openfhe("openfhe_length_mismatch", message, call, data)
}

stop_missing_key <- function(message, call = sys.call(-1), data = list()) {
  stop_openfhe("openfhe_missing_key", message, call, data)
}

stop_stale_pointer <- function(call = sys.call(-1)) {
  stop_openfhe(
    "openfhe_stale_pointer",
    paste0(
      "this object references encrypted state from an R session that has ",
      "ended (for example it was restored with readRDS()/load()).\n",
      "Encrypted objects and keys cannot be saved with R's own serialisation; ",
      "use save_fhe()/load_fhe() instead."
    ),
    call
  )
}

stop_scheme_error <- function(message, call = sys.call(-1), data = list()) {
  stop_openfhe("openfhe_scheme_error", message, call, data)
}

stop_context_mismatch <- function(message, call = sys.call(-1), data = list()) {
  stop_openfhe("openfhe_context_mismatch", message, call, data)
}
