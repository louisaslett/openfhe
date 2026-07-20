#' Homomorphic encryption context
#'
#' An `FHEContext` holds an OpenFHE crypto context: the scheme (CKKS, BFV or
#' BGV), its parameters, and -- as they are generated -- the evaluation keys
#' attached to it.  Create one with [fhe_context()]; almost every other
#' function in the package operates relative to a context.
#'
#' Contexts (and all other openfhe objects) reference native memory through
#' an external pointer, so they cannot be persisted with [saveRDS()] /
#' [save()]; use `save_fhe()`/`load_fhe()` (available from a later phase)
#' instead.  An object restored by R's own serialisation is "stale": it
#' prints as such and any use raises an error of class
#' `openfhe_stale_pointer`.
#'
#' @slot ptr External pointer to the native OpenFHE crypto context.
#' @slot scheme The scheme: `"CKKS"`, `"BFV"` or `"BGV"`.
#' @slot params Named list of the normalised parameters the context was
#'   created with (see [fhe_context()]).
#' @slot features Character vector of enabled OpenFHE feature sets.
#' @slot cache Environment caching context facts (ring dimension, slot
#'   count, ...) and key-generation state, used for fast introspection and
#'   good error messages.
#'
#' @seealso [fhe_context()]
#' @export
setClass(
  "FHEContext",
  slots = c(
    ptr      = "externalptr",
    scheme   = "character",
    params   = "list",
    features = "character",
    cache    = "environment"
  )
)

# Raise a classed error if `x` holds a stale external pointer (e.g. the
# object was restored with readRDS()/load() in a fresh session).
check_live <- function(x) {
  ptr <- if (isVirtualClass(class(x))) NULL else methods::slot(x, "ptr")
  if (xp_is_null_(ptr)) {
    stop_stale_pointer(call = sys.call(-1))
  }
  invisible(x)
}

#' @describeIn FHEContext-class Compact description of the context:
#'   scheme, ring dimension, slot count, depth, security and enabled
#'   features.
#' @param object An `FHEContext`.
#' @export
setMethod("show", "FHEContext", function(object) {
  cat(sprintf("<OpenFHE %s context>\n", object@scheme))
  if (xp_is_null_(object@ptr)) {
    cat("  (stale: restored from an earlier R session; recreate the context",
        "or use load_fhe())\n")
    return(invisible(object))
  }
  sec <- if (is.na(object@params$security)) {
    "none (toy parameters, NOT secure)"
  } else {
    sprintf("%d-bit", object@params$security)
  }
  cat(sprintf(
    "  ring dimension %d (%d slots) | mult depth %d | security: %s\n",
    ring_dim(object), slot_count(object), mult_depth(object), sec
  ))
  cat(sprintf("  features: %s\n", paste(object@features, collapse = ", ")))
  invisible(object)
})
