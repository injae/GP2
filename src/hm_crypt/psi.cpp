#include <fmt/format.h>
#include <range/v3/all.hpp>

#include "hm_crypt/psi.hpp"
#include "hm_crypt/hash.hpp"

namespace psi {
    using namespace ssl;

    // order = q g (- Zq*
    Bn find_generator(Bn& p, Bn& q) {
        Bn g; // generater
        do {
            g.random_inplace(p); // random value in Zp
            if (g.is_zero() or g.is_one()) continue;
            if((not g.mul(g, p).is_one()) && g.exp(q,p).is_one() && g.exp(p.sub(Bn::one()), p).is_one()) break;
        } while(true);
        return g;
    }

    PublicKeys setup(int bits) {
        PublicKeys keys;
        keys.p.random_safe_prime_inplace(bits);
        keys.q = keys.p.sub(Bn::one()).rshift_one();
        keys.g0 = psi::find_generator(keys.p,keys.q);
        keys.g1 = psi::find_generator(keys.p,keys.q);
        keys.g2 = psi::find_generator(keys.p,keys.q);

        return keys;
    }
    

    EqualValue equal_prover(Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& x, Bn& y0, Bn& y1) {
        auto r = PublicKeys::r(q);
        auto b0 = g0.exp(r, p);
        auto b1 = g1.exp(r, p);
        auto e = H({p, y0, y1 , b0, b1});
        auto z = r.sub(e.mul(x, q),q);
        return {b0, b1, z};
    }

    bool equal_verifier(EqualValue& pi, Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& y0, Bn& y1){
        auto& [b0, b1, z] = pi;
        auto e = H({p, y0, y1, b0, b1});
        auto v0 = g0.exp(z,p).mul(y0.exp(e,p), p);
        auto v1 = g1.exp(z,p).mul(y1.exp(e,p), p);
        return b0 == v0 and b1 == v1;
    }

    /// return pi2 = (b, z0, z1)
    ProofValue two_prover(Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& x0, Bn x1, Bn& y) { 
        ProofValue pi;
        auto r0 = PublicKeys::r(q);
        auto r1 = PublicKeys::r(q);
        pi.b = g0.exp(r0,p).mul(g1.exp(r1,p), p);
        auto e = H({p, y, pi.b});
        pi.z0 = r0.sub(e.mul(x0, q),q);
        pi.z1 = r1.sub(e.mul(x1, q),q);
        return pi;
    }

    bool two_verifier(ProofValue& pi, Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& y) {
        auto& [b, z0, z1] = pi;
        auto e = H({ p, y, b });
        auto v =  g0.exp(z0,p).mul(g1.exp(z1,p).mul(y.exp(e,p),p), p);
        return b == v;
    }

    Bn H(std::vector<Bn>&& bns) {
        using namespace ranges;
        return sha256::hash_to_Bn(bns
                       | views::transform([](auto it) { return it.to_bytes(); })
                       | views::cache1
                       | views::join
                       | to_vector);
    }
}
