#ifndef CRYPTOMANAGER_H
#define CRYPTOMANAGER_H

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>
#include <vector>
#include <array>

constexpr size_t SIZE_KEY = 1024;

class CryptoManager
{
public:
    CryptoManager();
    bool save_symetric_key(const std::vector<uint8_t>& encrypted_symetric_key);
    std::array<uint8_t, 160> get_public_key();
    bool set_AES_key(const std::vector<uint8_t>& encrypted_symetric_key);
    std::vector<uint8_t> encrypt_file(const std::vector<uint8_t>& file_content);
    std::string get_Private_Key();

private:
    CryptoPP::RSA::PrivateKey _privateKey;
    CryptoPP::RSA::PublicKey _publicKey;
    CryptoPP::SecByteBlock _AESkey;
    void savePrivateKey();
    bool load_priv_key();
    
    
};

#endif