#pragma once

#ifndef __SECURE_PSI_HPP__
#define __SECURE_PSI_HPP__

#include "hm_crypt/bn.hpp"
#include <tuple>
#include <nlohmann/json.hpp>

namespace psi {
    using namespace ssl;
    /// public keys p g0 g1 g2 q
    struct PublicKeys {
        Bn p;
        Bn g0;
        Bn g1;
        Bn g2;
        Bn q;
        // random in range(q)
        inline Bn r() { return PublicKeys::r(q); }

        // random in range(q)
        inline static Bn r(const Bn& q) { Bn r;
            do {r.random_inplace(q);}while(r.is_zero());
            return r;
        }
        // H1(x) = h = g0^x (mod p)
        inline Bn H1(Bn &x) {return g0.exp(x, p);}
    };

    struct ProofValue {Bn b; Bn z0; Bn z1;};
    struct EqualValue {Bn b0; Bn b1; Bn z;};

    // H(bsn), ex) H3(a || b|| c) == H(vector{a, b,c})
    Bn H(std::vector<Bn>&& bns); 

    // return g
    Bn find_generator(Bn& p, Bn& q);

    PublicKeys setup(int bits);

    // h = H1(x),  x (- Zq, h (- G
    Bn H1(PublicKeys& keys, Bn& x);

    // pi_eq := (β0, β1, z) pub keys (p,g,q,y0,y1) y0 = g0^x (mod p), y1 = g1^x (mod p)
    EqualValue equal_prover(Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& x, Bn& y0, Bn& y1);
    bool equal_verifier(EqualValue& pi, Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& y0, Bn& y1);

    // pi2(β, z0, z1) = g1^r0*g2^r1
    ProofValue two_prover(Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& x0, Bn x1, Bn& y);
    
    // true or false,  pub keys (pi2, p, g0, g1, q, y)
    bool two_verifier(ProofValue& pi, Bn& p, Bn& g0, Bn& g1, Bn& q, Bn& y);
}

namespace nlohmann {
    using namespace psi;
    template <> struct adl_serializer<PublicKeys> {
        static void to_json(json& j, const PublicKeys& value) {
            j["p"]  = value.p;
            j["g0"] = value.g0;
            j["g1"] = value.g1;
            j["g2"] = value.g2;
            j["q"]  = value.q;
        }
        static void from_json(const json& j, PublicKeys& value) {
            j["p"].get_to(value.p);
            j["g0"].get_to(value.g0);
            j["g1"].get_to(value.g1);
            j["g2"].get_to(value.g2);
            j["q"].get_to(value.q);
        }
    };
    template <> struct adl_serializer<ProofValue> {
        static void to_json(json& j, const ProofValue& value) {
            j["b"]  = value.b;
            j["z0"] = value.z0;
            j["z1"] = value.z1;
        }
        static void from_json(const json& j, ProofValue& value) {
            j["b"].get_to(value.b);
            j["z0"].get_to(value.z0);
            j["z1"].get_to(value.z1);
        }
    };

    template <> struct adl_serializer<EqualValue> {
        static void to_json(json& j, const EqualValue& value) {
            j["z"]  = value.z;
            j["b0"] = value.b0;
            j["b1"] = value.b1;
        }
        static void from_json(const json& j, EqualValue& value) {
            j["z"].get_to(value.z);
            j["b0"].get_to(value.b0);
            j["b1"].get_to(value.b1);
        }
    };
}


#endif
