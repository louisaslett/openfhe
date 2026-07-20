#include "r_shim/r_stream.h"

#include <streambuf>

#include <R_ext/Print.h>

namespace {

class r_printf_buf : public std::streambuf {
 public:
    explicit r_printf_buf(bool to_stderr) : to_stderr_(to_stderr) {}

 protected:
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (to_stderr_) {
            REprintf("%.*s", static_cast<int>(n), s);
        } else {
            Rprintf("%.*s", static_cast<int>(n), s);
        }
        return n;
    }

    int overflow(int c) override {
        if (c != traits_type::eof()) {
            char ch = static_cast<char>(c);
            xsputn(&ch, 1);
        }
        return c;
    }

 private:
    bool to_stderr_;
};

r_printf_buf rcout_buf(false);
r_printf_buf rcerr_buf(true);

}  // namespace

namespace lbcrypto {
std::ostream RCout(&rcout_buf);
std::ostream RCerr(&rcerr_buf);
}  // namespace lbcrypto
