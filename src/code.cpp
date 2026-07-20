// Phase 1 smoke-test bindings: prove the vendored OpenFHE library compiles,
// links, and computes.  The real binding surface is added in later phases.
#include <algorithm>
#include <cmath>
#include <string>
#include <vector>

#include <cpp11.hpp>

#include "openfhe.h"

[[cpp11::register]] std::string openfhe_version_() {
    return GetOPENFHEVersion();
}

// Full C++-side CKKS round trip on toy (insecure) parameters:
// encrypt x, compute 2 * x^2 homomorphically, decrypt, and return the
// maximum absolute error against the plaintext computation.
[[cpp11::register]] double openfhe_selftest_() {
    using namespace lbcrypto;

    CCParams<CryptoContextCKKSRNS> params;
    params.SetSecurityLevel(HEStd_NotSet);  // toy parameters, NOT secure
    params.SetRingDim(512);
    params.SetMultiplicativeDepth(2);
    params.SetScalingModSize(40);
    params.SetBatchSize(8);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);

    KeyPair<DCRTPoly> kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);

    std::vector<double> x = {0.5, 1.5, -2.0, 3.25};
    Plaintext pt = cc->MakeCKKSPackedPlaintext(x);
    auto ct  = cc->Encrypt(kp.publicKey, pt);
    auto ct2 = cc->EvalAdd(ct, ct);    // 2x
    auto ct3 = cc->EvalMult(ct2, ct);  // 2x^2

    Plaintext out;
    cc->Decrypt(kp.secretKey, ct3, &out);
    out->SetLength(x.size());
    std::vector<double> v = out->GetRealPackedValue();

    double err = 0.0;
    for (std::size_t i = 0; i < x.size(); ++i) {
        err = std::max(err, std::fabs(v[i] - 2.0 * x[i] * x[i]));
    }
    return err;
}
