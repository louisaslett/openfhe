// Encryption, decryption and ciphertext introspection.
//
// The R level owns encoding policy (which scheme takes which R type, range
// and whole-number checks); these entry points just pack, encrypt and
// decrypt.  One R vector becomes ONE packed SIMD ciphertext; decryption
// calls SetLength() with the recorded true length so slot padding never
// reaches R.
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "glue.h"

using namespace lbcrypto;

[[cpp11::register]] SEXP enc_real_(CtxPtr ctx, PkPtr pk, cpp11::doubles x) {
    Ctx& cc = deref(ctx, "context");
    Pk& key = deref(pk, "public key");
    std::vector<double> v(x.begin(), x.end());
    Plaintext pt = cc->MakeCKKSPackedPlaintext(v);
    return CtPtr(new Ct(cc->Encrypt(key, pt)));
}

[[cpp11::register]] SEXP enc_int_(CtxPtr ctx, PkPtr pk, cpp11::doubles x) {
    Ctx& cc = deref(ctx, "context");
    Pk& key = deref(pk, "public key");
    std::vector<int64_t> v;
    v.reserve(static_cast<std::size_t>(x.size()));
    for (double xi : x)
        v.push_back(static_cast<int64_t>(std::llround(xi)));
    Plaintext pt = cc->MakePackedPlaintext(v);
    return CtPtr(new Ct(cc->Encrypt(key, pt)));
}

[[cpp11::register]] cpp11::writable::doubles dec_real_(CtxPtr ctx, SkPtr sk,
                                                       CtPtr ct, int n) {
    Ctx& cc = deref(ctx, "context");
    Sk& key = deref(sk, "secret key");
    Ct& c   = deref(ct, "ciphertext");
    Plaintext out;
    cc->Decrypt(key, c, &out);
    out->SetLength(static_cast<std::size_t>(n));
    std::vector<double> v = out->GetRealPackedValue();
    return cpp11::writable::doubles(v.begin(), v.end());
}

[[cpp11::register]] cpp11::writable::doubles dec_int_(CtxPtr ctx, SkPtr sk,
                                                      CtPtr ct, int n) {
    Ctx& cc = deref(ctx, "context");
    Sk& key = deref(sk, "secret key");
    Ct& c   = deref(ct, "ciphertext");
    Plaintext out;
    cc->Decrypt(key, c, &out);
    out->SetLength(static_cast<std::size_t>(n));
    const std::vector<int64_t>& v = out->GetPackedValue();
    cpp11::writable::doubles res(static_cast<R_xlen_t>(v.size()));
    for (std::size_t i = 0; i < v.size(); ++i)
        res[static_cast<R_xlen_t>(i)] = static_cast<double>(v[i]);
    return res;
}

[[cpp11::register]] int ct_level_(CtPtr ct) {
    return static_cast<int>(deref(ct, "ciphertext")->GetLevel());
}
