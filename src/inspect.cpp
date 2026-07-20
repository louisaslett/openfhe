// Human-readable dumps of the raw polynomial contents of keys and
// ciphertexts.  Never used by computation; exposed so users can see exactly
// what an encrypted object is made of (as.character() methods in R).
#include <sstream>
#include <string>

#include "glue.h"

using namespace lbcrypto;

namespace {

template <typename Elems>
std::string dump_elements(const Elems& elems) {
    std::ostringstream os;
    for (std::size_t i = 0; i < elems.size(); ++i)
        os << "polynomial " << i << ":\n" << elems[i] << "\n";
    return os.str();
}

}  // namespace

[[cpp11::register]] std::string ct_text_(CtPtr ct) {
    return dump_elements(deref(ct, "ciphertext")->GetElements());
}

[[cpp11::register]] std::string pk_text_(PkPtr pk) {
    return dump_elements(deref(pk, "public key")->GetPublicElements());
}

[[cpp11::register]] std::string sk_text_(SkPtr sk) {
    std::ostringstream os;
    os << "polynomial 0:\n" << deref(sk, "secret key")->GetPrivateElement()
       << "\n";
    return os.str();
}
