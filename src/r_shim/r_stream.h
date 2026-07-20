// R-safe replacements for std::cout / std::cerr used by the vendored OpenFHE
// sources.  CRAN policy forbids compiled code writing to stdout/stderr, so
// tools/vendor.R rewrites every std::cout / std::cerr reference in the
// vendored tree to lbcrypto::RCout / lbcrypto::RCerr, which flush through
// R's Rprintf / REprintf instead.
#ifndef OPENFHE_R_SHIM_R_STREAM_H
#define OPENFHE_R_SHIM_R_STREAM_H

#include <ostream>

namespace lbcrypto {
extern std::ostream RCout;
extern std::ostream RCerr;
}  // namespace lbcrypto

#endif  // OPENFHE_R_SHIM_R_STREAM_H
