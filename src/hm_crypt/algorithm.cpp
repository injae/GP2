#include "hm_crypt/algorithm.hpp"

namespace hmc::util {
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
}
