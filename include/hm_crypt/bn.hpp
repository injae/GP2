#ifndef __SECURE_BN_HPP__
#define __SECURE_BN_HPP__

#include <string>
#include <cstdint>

#include <openssl/bn.h>
#include <openssl/rand.h>

#include <serdepp/serde.hpp>

namespace ssl {
    class Bn
    {
    public:
        ///< ctors and dtor
        Bn(void);
        Bn(const int rhs);
        Bn(const Bn& rhs);
        Bn(const u_int8_t* bytes, const size_t len);
        Bn(const std::vector<u_int8_t>& bytes);
        Bn(const std::string& str);
        virtual ~Bn(void);

        inline const static Bn zero(void) { const static Bn _zero(0); return _zero; }   
        inline const static Bn one(void)  { const static Bn _one(1);  return _one; }   
        inline const static Bn two(void)  { const static Bn _two(2);  return _two; }   
        bool is_one(void) const; 
        bool is_zero(void) const;    

        ///< size
        int byte_size(void) const;

        int bit_size(void) const;

        ///< choose a random and store itself
        void random_inplace(const Bn& range);
        void random_inplace(const int bits);
        void random_safe_prime_inplace(const int bits);

        ///< shift
        Bn rshift_one();
        Bn lshift_one();

        ///< arithmetic operations
        Bn mod(const Bn& p) const;                               ///< return this mod p
        void mod_inplace(const Bn& p);                           ///< this = this mod p
        Bn negate(const Bn& p=NULL) const;                       ///< return -this mod p
        void negate_inplace(const Bn& p=NULL);                   ///< this = -this mod p
        Bn add(const Bn& x, const Bn& p=NULL) const;             ///< return this + x mod p
        void add_inplace(const Bn& x, const Bn& p=NULL);         ///< this = this + x mod p
        Bn sub(const Bn& x, const Bn& p=NULL) const;             ///< return this - x mod p
        void sub_inplace(const Bn& x, const Bn& p=NULL);         ///< this = this - x mod p
        Bn mul(const Bn& x, const Bn& p) const;             ///< return this * x mod p
        Bn mul(const Bn& x) const;             ///< return this * x mod p
        void mul_inplace(const Bn& x, const Bn& p=NULL);         ///< this = this * x mod p
        Bn div(const Bn& x) const;             ///< return this * x mod p
        Bn inv(const Bn& p=NULL) const;                          ///< return this^{-1} mod p
        void inv_inplace(const Bn& p=NULL);                      ///< this = this^{-1} mod p
        Bn exp(const Bn& x, const Bn& p) const;             ///< return this ^ x mod p
        Bn exp(const Bn& x) const;             ///< return this ^ x mod p
        void exp_inplace(const Bn& x, const Bn& p=NULL);         ///< this = this ^ x mod p
        ///< primality test
        bool is_prime(void) const;
        Bn gcd(const Bn& x) const;                          ///< gcd(this, x)

        ///< overloading operations
        Bn& operator=(const int rhs);                       ///< this <- rhs
        Bn& operator=(const Bn& rhs);     

        bool operator==(const Bn& rhs) const;
        bool operator!=(const Bn& rhs) const;
        bool operator<(const Bn& rhs) const;

        // BN& operator+=(const BN& rhs);
        // BN& operator-=(const BN& rhs);
        // BN& operator*=(const BN& rhs);

        ///< input
        void from_dec(const char* dec);
        void from_hex(const char* hex);
        void from_bytes(const uint8_t* bytes, const int len);

        ///< output
        static std::string bn_to_dec(const Bn& bn);
        static std::string bn_to_hex(const Bn& bn);    
        std::string to_dec(void) const;
        std::string to_hex(void) const;
        std::string to_string();
        void to_bytes(uint8_t* bytes, int* len) const;
        std::vector<uint8_t> to_bytes();

        //! bitwise xor
        BN   _xor(const BN& x) const;
        void _xorInplace(const BN& x);

    private:
        BN_CTX* ctx_;       ///< context
        BIGNUM* ptr_;       ///< pointer to the big number 
    };
}

namespace serde {
    using namespace ssl;
    template<typename serde_ctx>
        struct serde_serializer<Bn, serde_ctx> {
        inline static auto from(serde_ctx& ctx, Bn& data, std::string_view key) {
            std::string temp="";
            serde_adaptor<typename serde_ctx::Adaptor, std::string>::from(ctx.adaptor, key, temp);
            data.from_hex(temp.c_str());
        }
        inline static auto into(serde_ctx& ctx, const Bn& data, std::string_view key) {
            std::string buf = data.to_hex();
            serde_adaptor<typename serde_ctx::Adaptor, std::string>::into(ctx.adaptor, key, buf);
        }
    };
}

#endif 
