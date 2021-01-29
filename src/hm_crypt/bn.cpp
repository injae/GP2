#include <cassert>
#include <cstring>
#include <fmt/format.h>
#include <string>

#include "hm_crypt/bn.hpp"

namespace ssl {
    Bn::Bn(void) {
        ctx_ = BN_CTX_new();
        ptr_ = BN_new();
    }

    Bn::Bn(const int rhs): Bn() {
        if (0 <= rhs) { ///< a positive integer or zero
            BN_set_word(ptr_, static_cast<unsigned long>(rhs));
        }
        else {
            BN_set_word(ptr_, static_cast<unsigned long>(-rhs));
            BN_set_negative(ptr_, 1);
        }
    }

    Bn::Bn(const Bn& rhs): Bn() {
        BN_copy(ptr_, rhs.ptr_);
    }

    Bn::Bn(const u_int8_t* bytes, const size_t len) : Bn() {
        BN_bin2bn(bytes, len, ptr_);  ///< store the given binary string into an openssl big num
    }

    Bn::Bn(const std::string& str) : Bn() {
        std::vector<uint8_t> bin(str.begin(), str.end());
        bin.push_back('\0');
        ptr_ = BN_bin2bn(&bin[0], bin.size()-1, NULL);
    }

    Bn::~Bn(void) {
        ///< destroy all objects
        BN_CTX_free(ctx_);
        BN_clear_free(ptr_);
    }

    void Bn::random_inplace(const Bn& range) {
        ///< pick a random value between 0 and range and store itself
        BN_rand_range(ptr_, range.ptr_);
    }

    void Bn::random_inplace(const int bits) {
        ///< pick a random value whose length is bits and store itself
        ///< the 3rd parameter 0: MSB can be set 1
        ///< the 4th parameter 1: LSB can be set 1 (i.e., an odd integer)
        BN_rand(ptr_, bits, 0, 1);
    }

    void Bn::random_safe_prime_inplace(const int bits) {
        if(!BN_generate_prime_ex(ptr_, bits, 1, NULL, NULL, NULL)) {
            fmt::print(stderr, "can't generate safe prime"); exit(1);
        }
    }


    Bn Bn::rshift_one() {
        Bn ret; 
        if(!BN_rshift1(ret.ptr_, ptr_)){
            fmt::print(stderr, "can't right shift 1"); exit(1);
        }
        return ret;
    }

    Bn Bn::lshift_one() {
        Bn ret; 
        if(!BN_lshift1(ret.ptr_, ptr_)){
            fmt::print(stderr, "can't left shift 1"); exit(1);
        }
        return ret;
    }

    ///< res = this + x mod p
    Bn Bn::add(const Bn& x, const Bn& p) const
    {
        Bn res;
        BN_mod_add(res.ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);

        return res;
    }

    void Bn::add_inplace(const Bn& x, const Bn& p)
    {
        ///< this = this + x mod p
        BN_mod_add(this->ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);
    }

    Bn Bn::mod(const Bn& p) const {
        Bn res;
        ///< res = x mod p
        BN_mod(res.ptr_, this->ptr_, p.ptr_, ctx_);

        return res;
    }

    ///< this = this mod p
    void Bn::mod_inplace(const Bn& p) {
        BN_mod(ptr_, ptr_, p.ptr_, ctx_);
    }

    void Bn::from_dec(const char* dec) {
        BN_dec2bn(&this->ptr_, dec);
    }

    void Bn::from_hex(const char* hex) {
        BN_hex2bn(&this->ptr_, hex);
    }

    void Bn::from_bytes(const uint8_t* bytes, const int len) {
        assert(0 != ptr_);
        BN_bin2bn(bytes, len, this->ptr_);
    }

    std::string Bn::to_dec(void) const {
        std::string res = "";
        char*       dec = 0;

        dec = BN_bn2dec(this->ptr_);
        for (auto i = 0; i < std::strlen(dec); i++) {
            res = res + dec[i];
        }

        return res;
    }

    std::string Bn::bn_to_dec(const Bn& bn) {
        std::string res = "";
        char*       dec = 0;

        dec = BN_bn2dec(bn.ptr_);
        for (auto i = 0; i < std::strlen(dec); i++) {
            res = res + dec[i];
        }

        return res;
    }

    std::string Bn::to_hex(void) const
    {
        std::string res = "";
        char*       hex = 0;

        hex = BN_bn2hex(this->ptr_);
        for (auto i = 0; i < std::strlen(hex); i++) {
            res = res + hex[i];
        }

        return res;
    }

    std::string Bn::bn_to_hex(const Bn& bn) {
        std::string res = "";
        char*       hex = 0;

        hex = BN_bn2hex(bn.ptr_);
        for (auto i = 0; i < std::strlen(hex); i++) {
            res = res + hex[i];
        }

        return res;
    }

    void Bn::to_bytes(uint8_t* bytes, int* len) const
    {
        assert(0 != bytes);
        *len = BN_bn2bin(this->ptr_, bytes);
    }

    std::string Bn::to_string() {
        auto bytes = to_bytes();
        return std::string{bytes.begin(), bytes.end()};
    }

    std::vector<uint8_t> Bn::to_bytes() {
        std::vector<uint8_t> result;
        uint8_t buffer[1000] = {0};
        auto len = BN_bn2bin(this->ptr_, buffer);
        result.resize(len);
        std::memcpy(&result[0], &buffer[0], len*sizeof(uint8_t));
        return result;
    }

    int Bn::bit_size(void) const
    {
        return BN_num_bits(this->ptr_);
    }

    int Bn::byte_size(void) const
    {
        return BN_num_bytes(this->ptr_);
    }

    Bn& Bn::operator=(const int rhs) {
        if (0 < rhs) {
            BN_set_word(ptr_, static_cast<unsigned long>(rhs));
        }
        else {
            BN_set_word(ptr_, static_cast<unsigned long>(-rhs));
            BN_set_negative(ptr_, 1);
        }
        return *this;
    }

    Bn& Bn::operator=(const Bn& rhs) {
        BN_copy(this->ptr_, rhs.ptr_);

        return *this;
    }

    Bn Bn::sub(const Bn& x, const Bn& p) const {
        Bn res;

        ///< res = this - x mod p
        BN_mod_sub(res.ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);

        return res;
    }

    ///< this = this - x mod p
    void Bn::sub_inplace(const Bn& x, const Bn& p) {
        BN_mod_sub(ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);

        return;
    }

    Bn Bn::mul(const Bn& x, const Bn& p) const {
        Bn res;

        ///< res = this * x mod p
        BN_mod_mul(res.ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);

        return res;
    }

    Bn Bn::mul(const Bn& x) const {
        Bn res;

        ///< res = this * x mod p
        BN_mul(res.ptr_, this->ptr_, x.ptr_, ctx_);

        return res;
    }

    void Bn::mul_inplace(const Bn& x, const Bn& p)  
    {
        ///< this = this * x mod p
        BN_mod_mul(this->ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);

        return;
    }

    Bn Bn::inv(const Bn& p) const
    {
        Bn res;
        ///< res = 1 /this mod p
        BN_mod_inverse(res.ptr_, this->ptr_, p.ptr_, ctx_);

        return res;
    }

    void Bn::inv_inplace(const Bn& p) {
        ///< this = 1/this mod p
        BN_mod_inverse(this->ptr_, this->ptr_, p.ptr_, ctx_);

        return;
    }

    Bn Bn::exp(const Bn& x, const Bn& p) const {
        Bn res;
        ///< res = this ^ x mod p
        BN_mod_exp(res.ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);
        return res;
    }

    Bn Bn::exp(const Bn& x) const {
        Bn res;
        ///< res = this ^ x mod p
        BN_exp(res.ptr_, this->ptr_, x.ptr_, ctx_);
        return res;
    }

    void Bn::exp_inplace(const Bn& x, const Bn& p) {
        ///< this = this ^ x mod p
        BN_mod_exp(this->ptr_, this->ptr_, x.ptr_, p.ptr_, ctx_);

        return;
    }

    Bn Bn::negate(const Bn& p) const {
        Bn res;

        if (BN_is_zero(ptr_)) {
            return Bn();
        }
        ///< res = p - this
        BN_sub(res.ptr_, p.ptr_, ptr_);

        return res;
    }

    void Bn::negate_inplace(const Bn& p)
    {
        if (BN_is_zero(ptr_)) {
            return;
        }
        ///< this = p - this
        BN_sub(ptr_, p.ptr_, ptr_);

        return;
    }

    /**
    * @fn      bool _openssl_BN::_isPrime(void) const
    * @brief   The Miller-Rabin primality test
    * 
    */
    bool Bn::is_prime(void) const
    {
        ///< run the Miller-Rabin probabilistic primality test
        ///< the iteration number is 64 by default
        if (0 < BN_is_prime_ex(this->ptr_, BN_prime_checks, ctx_, 0)) {
            return true;
        }
        else {
            return false;
        }
    }

    bool Bn::is_one(void) const 
    { 
        if (BN_is_one(ptr_)) {
            return true;
        } else {
            return false;
        }
    } 

    bool Bn::is_zero(void) const 
    { 
        if (BN_is_zero(ptr_)) {
            return true;
        }
        else {
            return false;
        }
    }

    bool Bn::operator==(const Bn &rhs) const{
      ///< check if this == rhs
      return 0 == BN_cmp(this->ptr_, rhs.ptr_);
    }

    bool Bn::operator!=(const Bn& rhs) const{
        return !(*this == rhs);
    }

    bool Bn::operator<(const Bn& rhs) const{
        return -1 == BN_cmp(this->ptr_, rhs.ptr_);
    }

    Bn Bn::gcd(const Bn& x) const {
        Bn res;
        ///< res = gcd(this, x)
        BN_gcd(res.ptr_, this->ptr_, x.ptr_, ctx_);

        return res;
    }


    Bn Bn::div(const Bn& x) const {
        Bn div;
        Bn rem;
        BN_div(div.ptr_, rem.ptr_, this->ptr_, x.ptr_, ctx_);
        return div;
    }             

}
