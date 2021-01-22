#pragma once

#ifndef HM_CRYPT_ALGORITHM_HPP
#define HM_CRYPT_ALGORITHM_HPP

#include "hm_crypt/bn.hpp"
#include <functional>

namespace hmc::util {
    using namespace ssl;
    inline Bn random(const Bn& q, std::function<bool(const Bn&)>&& condition) {
        Bn r;
        do {r.random_inplace(q);}while(not condition(r));
        return r;
    }

    Bn find_generator(Bn& p, Bn& q);

    struct safe_prime {
        Bn p;
        Bn q;
        static inline safe_prime generate(int bits) {
            safe_prime primes;
            primes.p.random_safe_prime_inplace(bits);
            primes.q = primes.p.sub(Bn::one()).rshift_one();
            return primes;
        }
    };

};

#endif
