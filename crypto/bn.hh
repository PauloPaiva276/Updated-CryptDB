#pragma once

#include <stdexcept>
#include <ostream>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include <util/errstream.hh>

class _BN_new_ctx {
public:
    _BN_new_ctx() { c = BN_CTX_new(); }
    ~_BN_new_ctx() { BN_CTX_free(c); }
    BN_CTX *ctx() { return c; }

    static BN_CTX *the_ctx() {
        static _BN_new_ctx cx;
        return cx.ctx();
    }

private:
    BN_CTX *c;
};

class BN_new {
public:
    BN_new() {
        BN_init(&b);
    }

    BN_new(unsigned long v) {
        BN_init(&b);
        BN_set_word(&b, v);
    }

    BN_new(const BN_new &other) {
        BN_init(&b);
        throw_c(BN_copy(&b, other.bn()));
    }

    BN_new(const uint8_t *buf, size_t nbytes) {
        BN_init(&b);
        throw_c(BN_bin2bn(buf, nbytes, &b));
    }

    BN_new(const std::string &v) {
        BN_init(&b);
        throw_c(BN_bin2bn(reinterpret_cast<const uint8_t*>(v.data()), v.size(), &b));
    }

    ~BN_new() { BN_free(&b); }

    BIGNUM *bn() { return &b; }
    const BIGNUM *bn() const { return &b; }
    unsigned long word() const {
        unsigned long v = BN_get_word(&b);
        if (v == 0xffffffffL)
            throw std::runtime_error("out of range");
        return v;
    }

#define op(opname, func, args...)                               \
    BN_new opname(const BN_new &mod) {                          \
        BN_new res;                                             \
        throw_c(1 == func(res.bn(), &b, mod.bn(), ##args));      \
        return res;                                             \
    }

    op(operator+, BN_add)
    op(operator-, BN_sub)
    op(operator%, BN_mod, _BN_new_ctx::the_ctx())
    op(operator*, BN_mul, _BN_new_ctx::the_ctx())
#undef op

#define pred(predname, cmp)                                     \
    bool predname(const BN_new &other) {                        \
        return BN_cmp(&b, other.bn()) cmp;                      \
    }

    pred(operator<,  <  0)
    pred(operator<=, <= 0)
    pred(operator>,  >  0)
    pred(operator>=, >= 0)
    pred(operator==, == 0)
#undef pred

    BN_new invmod(const BN_new &mod) {
        BN_new r;
        throw_c(BN_mod_inverse(r.bn(), &b, mod.bn(), _BN_new_ctx::the_ctx()));
        return r;
    }

private:
    BIGNUM b;
};

static inline std::ostream&
operator<<(std::ostream &out, const BN_new &bn)
{
    char *s = BN_bn2dec(bn.bn());
    out << s;
    OPENSSL_free(s);
    return out;
}
