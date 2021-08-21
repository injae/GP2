#pragma once

#ifndef HM_CRYPT_ALGORITHM_HPP
#define HM_CRYPT_ALGORITHM_HPP

#include "hm_crypt/bn.hpp"
#include <functional>

#define __debug

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
            //! confirmation of primality
            assert(true == primes.p.is_prime());
            assert(true == primes.q.is_prime());

#ifdef __debug
            printf("modulus p of %d-bit: ", primes.p.bit_size());
            for (int i = 0; i < primes.p.byte_size(); i++) {
                printf("%02x", primes.p.to_bytes()[i]);
            }
            printf("\nsubgroup order q of %d-bit: ", primes.q.bit_size());
            for (int i = 0; i < primes.q.byte_size(); i++) {
                printf("%02x", primes.q.to_bytes()[i]);
            }
            printf("\n");
#endif
            return primes;
        }
    };

};

#endif
