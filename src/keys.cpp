// Key generation: public/secret key pairs and evaluation keys.
//
// Evaluation keys (relinearisation, sum, rotation) are stored by OpenFHE
// inside the crypto context itself; only the key pair comes back to R as
// external pointers.  R-level key-state bookkeeping lives in FHEContext@cache.
#include <vector>

#include "glue.h"

using namespace lbcrypto;

[[cpp11::register]] cpp11::list keygen_(CtxPtr ctx, bool sum) {
    Ctx& cc = deref(ctx, "context");
    KeyPair<DCRTPoly> kp = cc->KeyGen();
    if (!kp.good())
        cpp11::stop("OpenFHE key generation failed");
    cc->EvalMultKeyGen(kp.secretKey);
    if (sum)
        cc->EvalSumKeyGen(kp.secretKey);
    using namespace cpp11::literals;
    return cpp11::writable::list({"pk"_nm = PkPtr(new Pk(kp.publicKey)),
                                  "sk"_nm = SkPtr(new Sk(kp.secretKey))});
}

[[cpp11::register]] void rot_keygen_(CtxPtr ctx, SkPtr sk, cpp11::integers idx) {
    Ctx& cc = deref(ctx, "context");
    Sk& key = deref(sk, "secret key");
    std::vector<int32_t> indices(idx.begin(), idx.end());
    cc->EvalRotateKeyGen(key, indices);
}
