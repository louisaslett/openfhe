# Toy contexts for tests: tiny, fast, INSECURE (security = NA).
#
# Note ring_dim 1024: OpenFHE 1.5.1 rejects the BGV/depth-2/ring-512 corner
# (EstimateLogP failure in hybrid key switching); 1024 works for all schemes.
toy <- function(scheme = "CKKS", ...) {
  fhe_context(scheme, mult_depth = 2, security = NA, ring_dim = 1024, ...)
}
