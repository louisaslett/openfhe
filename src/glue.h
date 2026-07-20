// Shared declarations for the cpp11 binding glue (src/*.cpp).
#ifndef OPENFHE_GLUE_H
#define OPENFHE_GLUE_H

#include <cpp11.hpp>

#include "openfhe.h"

using Ctx = lbcrypto::CryptoContext<lbcrypto::DCRTPoly>;
using Ct  = lbcrypto::Ciphertext<lbcrypto::DCRTPoly>;
using Pk  = lbcrypto::PublicKey<lbcrypto::DCRTPoly>;
using Sk  = lbcrypto::PrivateKey<lbcrypto::DCRTPoly>;

using CtxPtr = cpp11::external_pointer<Ctx>;
using CtPtr  = cpp11::external_pointer<Ct>;
using PkPtr  = cpp11::external_pointer<Pk>;
using SkPtr  = cpp11::external_pointer<Sk>;

// Dereference an external pointer, failing loudly if it is stale (NULL).
// R-level code performs its own check first (check_live(), which raises a
// classed openfhe_stale_pointer condition); this is the C++ backstop.
template <typename T>
inline T& deref(cpp11::external_pointer<T>& xp, const char* what) {
    T* p = xp.get();
    if (p == nullptr) {
        cpp11::stop(
            "stale openfhe %s pointer: the object comes from an R session that "
            "has ended; use save_fhe()/load_fhe() to persist encrypted objects",
            what);
    }
    return *p;
}

#endif  // OPENFHE_GLUE_H
