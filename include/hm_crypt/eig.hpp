#pragma once

#ifndef HM_CRYPT_EIG_HPP
#define HM_CRYPT_EIG_HPP

#include "hm_crypt/bn.hpp"
#include "hm_crypt/algorithm.hpp"
#include <serdepp/utility.hpp>

namespace hmc::eig {
    using namespace ssl;
    namespace detail {
        struct seed_key {
            Bn p;
            Bn q;
            Bn g;
            seed_key(int bits);
        };
    }

    inline Bn random_r(const Bn& g) { return util::random(g.sub(Bn::one()), [](auto& r){ return Bn::one() < r; }); }

    struct cipher {
        derive_serde(cipher, ctx.TAG(u).TAG(v);)
        Bn u;
        Bn v;
        bool operator<(const cipher& rhs) const { return u < rhs.u; }
    };

    struct public_key {
        derive_serde(public_key, ctx.TAG(p).TAG(q).TAG(g);)
        Bn p;
        Bn q;
        Bn g;
        Bn y;
        Bn yi;
        public_key(int bits);
        public_key() {}
        cipher encrypt(const std::string& plain_text);
    };

    struct secret_key {
        Bn p;
        Bn q;
        Bn g;
        Bn x;
        secret_key(const public_key& pk, Bn& x) : p(pk.p), q(pk.q), g(pk.g), x(x) {}
        secret_key() {}
        std::string decrypt(const cipher& cipher);
    };

}


#endif
