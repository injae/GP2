#pragma once

#ifndef HM_CRYPT_EIG_HPP
#define HM_CRYPT_EIG_HPP

#include "hm_crypt/bn.hpp"
#include "hm_crypt/algorithm.hpp"
#include <serdepp/serde.hpp>

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

    // inline Bn random_r(const Bn& g) { return util::random(g.sub(Bn::one()), [](auto& r){ return Bn::one() < r; }); }
    //! g ==> q
    inline Bn random_r(const Bn& q) { return util::random(q.sub(Bn::one()), [](auto& r){ return Bn::one() < r; }); }

    struct cipher {
        DERIVE_SERDE(cipher,(&Self::u, "u")(&Self::v, "v"))
        Bn u;
        Bn v;
        bool operator<(const cipher& rhs) const { return u < rhs.u; }
    };

    struct public_key {
        DERIVE_SERDE(public_key,(&Self::p, "p")(&Self::q, "q")(&Self::g, "g");)
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
        DERIVE_SERDE(secret_key, (&Self::p, "p")(&Self::q, "q")(&Self::g, "g")(&Self::x, "x"))
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
