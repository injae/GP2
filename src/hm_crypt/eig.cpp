#include "hm_crypt/eig.hpp"
#include "hm_crypt/hash.hpp"

namespace hmc::eig {
    namespace detail {
        seed_key::seed_key(int bits) {
            auto [_p, _q] = util::safe_prime::generate(bits);
            p = _p;                         //! modulus
            q = _q;                         //! subgroup order
            g = util::find_generator(p, q); //! subgroup generator of order q
        }
    }

    // y is uninitialized need to init y
    public_key::public_key(int bits) {
        auto [_p, _q, _g] = detail::seed_key(bits);
        p = _p; q = _q; g = _g;
    }

    
    cipher public_key::encrypt(const std::string& m) {
         auto r = random_r(q);
         auto u = g.exp(r,p);
         auto v = Bn(m).mul(y.exp(r, p),p);
         return {u, v};
    }

    std::string secret_key::decrypt(const cipher& c) {
        auto [u, v] = c;
        auto zi = u.exp(x.negate(), p);
        // spread zi 
        // return u * Z  (Z = z1 * ... zn)
        return std::string{};
    }
}
