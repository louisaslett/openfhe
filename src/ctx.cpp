// Context creation and introspection.
#include <string>

#include "glue.h"

using namespace lbcrypto;

namespace {

int geti(const cpp11::list& o, const char* nm) {
    return cpp11::as_cpp<int>(o[nm]);
}

SecurityLevel sec_level(int bits) {
    switch (bits) {
        case 0:
            return HEStd_NotSet;
        case 128:
            return HEStd_128_classic;
        case 192:
            return HEStd_192_classic;
        case 256:
            return HEStd_256_classic;
        default:
            cpp11::stop("invalid security level: %d", bits);
    }
}

ScalingTechnique scaling_tech(const std::string& s) {
    if (s == "auto")
        return FLEXIBLEAUTO;
    if (s == "auto-ext")
        return FLEXIBLEAUTOEXT;
    if (s == "fixed")
        return FIXEDMANUAL;
    cpp11::stop("invalid scaling technique '%s'", s.c_str());
}

// Options common to all schemes; 0 means "not set" for ring_dim/batch_size.
template <typename SchemeParams>
void set_common(SchemeParams& p, const cpp11::list& o) {
    p.SetMultiplicativeDepth(static_cast<uint32_t>(geti(o, "mult_depth")));
    p.SetSecurityLevel(sec_level(geti(o, "security_bits")));
    if (int rd = geti(o, "ring_dim"))
        p.SetRingDim(static_cast<uint32_t>(rd));
    if (int bs = geti(o, "batch_size"))
        p.SetBatchSize(static_cast<uint32_t>(bs));
}

}  // namespace

[[cpp11::register]] SEXP ctx_new_(std::string scheme, cpp11::list opts) {
    Ctx cc;
    if (scheme == "CKKS") {
        CCParams<CryptoContextCKKSRNS> p;
        set_common(p, opts);
        p.SetScalingModSize(static_cast<uint32_t>(geti(opts, "scale_bits")));
        p.SetFirstModSize(static_cast<uint32_t>(geti(opts, "first_mod_bits")));
        p.SetScalingTechnique(
            scaling_tech(cpp11::as_cpp<std::string>(opts["scaling"])));
        cc = GenCryptoContext(p);
    } else if (scheme == "BFV") {
        CCParams<CryptoContextBFVRNS> p;
        set_common(p, opts);
        p.SetPlaintextModulus(static_cast<PlaintextModulus>(
            cpp11::as_cpp<double>(opts["plaintext_modulus"])));
        cc = GenCryptoContext(p);
    } else if (scheme == "BGV") {
        CCParams<CryptoContextBGVRNS> p;
        set_common(p, opts);
        p.SetPlaintextModulus(static_cast<PlaintextModulus>(
            cpp11::as_cpp<double>(opts["plaintext_modulus"])));
        cc = GenCryptoContext(p);
    } else {
        cpp11::stop("unknown scheme '%s'", scheme.c_str());
    }

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    if (cpp11::as_cpp<bool>(opts["bootstrap"]))
        cc->Enable(FHE);

    return CtxPtr(new Ctx(cc));
}

[[cpp11::register]] cpp11::list ctx_info_(CtxPtr xp) {
    Ctx& cc = deref(xp, "context");
    using namespace cpp11::literals;
    int ring_dim = static_cast<int>(cc->GetRingDimension());
    int batch    = static_cast<int>(cc->GetEncodingParams()->GetBatchSize());
    int towers   = static_cast<int>(
        cc->GetCryptoParameters()->GetElementParams()->GetParams().size());
    return cpp11::writable::list(
        {"ring_dim"_nm = ring_dim, "batch_size"_nm = batch, "towers"_nm = towers});
}

[[cpp11::register]] bool xp_is_null_(SEXP xp) {
    return TYPEOF(xp) == EXTPTRSXP && R_ExternalPtrAddr(xp) == nullptr;
}
