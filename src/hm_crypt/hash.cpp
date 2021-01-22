#include "hm_crypt/hash.hpp"

namespace ssl::sha256 {
    std::string hash_to_hex(const std::string& data) {
        std::string result(SHA256_DIGEST_LENGTH*2, ' ');
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx_;
        SHA256_Init(&ctx_);
        SHA256_Update(&ctx_, data.c_str(), strlen(data.c_str()));
        SHA256_Final(digest, &ctx_);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
            sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);
        return result;
    }

    std::string hash_to_str(const std::string& data) {
        std::string result(SHA256_DIGEST_LENGTH, ' ');
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx_;
        SHA256_Init(&ctx_);
        SHA256_Update(&ctx_, data.c_str(), strlen(data.c_str()));
        SHA256_Final(digest, &ctx_);
        result.assign(digest, digest + SHA256_DIGEST_LENGTH);
        return result;
    }

    std::array<uint8_t, SHA256_DIGEST_LENGTH> hash(const std::string& data) {
        std::array<uint8_t,SHA256_DIGEST_LENGTH> digest;
        SHA256_CTX ctx_;
        SHA256_Init(&ctx_);
        SHA256_Update(&ctx_, data.c_str(), strlen(data.c_str()));
        SHA256_Final(digest.data(), &ctx_);
        return digest;
    }

    Bn hash_to_Bn(const std::vector<uint8_t>& data) {
        Bn bn;
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx_;
        SHA256_Init(&ctx_);
        SHA256_Update(&ctx_, &data[0], data.size());
        SHA256_Final(digest, &ctx_);
        bn.from_bytes(digest, SHA256_DIGEST_LENGTH);
        return bn;
    }

    Bn hash_to_Bn(const std::string& data) {
        Bn bn;
        uint8_t digest[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx_;
        SHA256_Init(&ctx_);
        SHA256_Update(&ctx_, data.c_str(), data.length());
        SHA256_Final(digest, &ctx_);
        bn.from_bytes(digest, SHA256_DIGEST_LENGTH);
        return bn;
    }
}

namespace ssl::sha1 {
    std::string hash_to_hex(const std::string& data) {
        std::string result(SHA_DIGEST_LENGTH*2, ' ');
        uint8_t digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx_;
        SHA1_Init(&ctx_);
        SHA1_Update(&ctx_, data.c_str(), strlen(data.c_str()));
        SHA1_Final(digest, &ctx_);
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);
        return result;
    }

    std::string hash_to_str(const std::string& data) {
        std::string result(SHA_DIGEST_LENGTH, ' ');
        uint8_t digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx_;
        SHA1_Init(&ctx_);
        SHA1_Update(&ctx_, data.c_str(), strlen(data.c_str()));
        SHA1_Final(digest, &ctx_);
        result.assign(digest, digest + SHA_DIGEST_LENGTH);
        return result;
    }



    std::array<uint8_t, SHA_DIGEST_LENGTH> hash(const std::string& data) {
        std::array<uint8_t,SHA_DIGEST_LENGTH> digest;
        SHA_CTX ctx_;
        SHA1_Init(&ctx_);
        SHA1_Update(&ctx_, data.c_str(), strlen(data.c_str()));
        SHA1_Final(digest.data(), &ctx_);
        return digest;
    }
    Bn hash_to_Bn(const std::vector<uint8_t>& data) {
        Bn bn;
        uint8_t digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx_;
        SHA1_Init(&ctx_);
        SHA1_Update(&ctx_, &data[0], data.size());
        SHA1_Final(digest, &ctx_);
        bn.from_bytes(digest, SHA_DIGEST_LENGTH);
        return bn;
        
    }
    Bn hash_to_Bn(const std::string& data) {
        Bn bn;
        uint8_t digest[SHA_DIGEST_LENGTH];
        SHA_CTX ctx_;
        SHA1_Init(&ctx_);
        SHA1_Update(&ctx_, data.c_str(), data.length());
        SHA1_Final(digest, &ctx_);
        bn.from_bytes(digest, SHA_DIGEST_LENGTH);
        return bn;
    }
}
