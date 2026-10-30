#include "CryptoManager.hpp"
#include "Transfer_json.hpp"

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/secblock.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/modes.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Constructor
CryptoManager::CryptoManager()
{
    CryptoPP::AutoSeededRandomPool rng; // random number generator
    if (!load_priv_key()){ // if no private key from old connection
        _privateKey.GenerateRandomWithKeySize(rng, SIZE_KEY);
        savePrivateKey(); // save the key to file
    }
    _publicKey.AssignFrom(_privateKey);
}

// Save private key to priv.key file
void CryptoManager::savePrivateKey()
{
    std::string private_key;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(private_key), false);
    _privateKey.DEREncode(encoder);
    encoder.MessageEnd();
    std::filesystem::path priv_key_path = Transfer_json::get_exe_dir() / "priv.key";
    std::ofstream priv_key(priv_key_path, std::ios::binary | std::ios::trunc);
    if (!priv_key.is_open())
        throw std::runtime_error("Error opening file priv.key");
    priv_key << private_key;
    priv_key.close();
}

// Encrypt file with AES to send
std::vector<uint8_t> CryptoManager::encrypt_file(
    const std::vector<uint8_t>& file_content){
    std::vector<uint8_t> encrypted_file;
    uint8_t iv[CryptoPP::AES::BLOCKSIZE] = {0};
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption cbcEncryption(
        this->_AESkey.data(), 
        this->_AESkey.size(), 
        iv
    );
    CryptoPP::StreamTransformationFilter filter(
        cbcEncryption, 
        new CryptoPP::VectorSink(encrypted_file)
    );

    filter.Put(file_content.data(), file_content.size());
    filter.MessageEnd();
    return encrypted_file;
    
}


// Load private key from priv.key
bool CryptoManager:: load_priv_key()
{
    std::filesystem::path priv_key_path = Transfer_json::get_exe_dir() / "priv.key";
    std::ifstream priv_key(priv_key_path, std::ios::binary);
    if (!priv_key.is_open())
        return false; // no private key
    std::string priv_key_str((std::istreambuf_iterator<char>(priv_key)),
                             std::istreambuf_iterator<char>());
    CryptoPP::ByteQueue queue; 
    CryptoPP::StringSource ss(priv_key_str,
                              true,
                              new CryptoPP::Base64Decoder(new CryptoPP::Redirector(queue)));
    this->_privateKey.BERDecode(queue);
    return true;  // private key found and loaded
}

// use private key to decrypt AES key that arrive from server and save 
bool CryptoManager::set_AES_key(const std::vector<uint8_t>& encrypted_symetric_key) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(_privateKey);
        this->_AESkey.New(32); 
        
        CryptoPP::ArraySink sink(this->_AESkey.data(), this->_AESkey.size());
        CryptoPP::StringSource ss(encrypted_symetric_key.data(), 
                                  encrypted_symetric_key.size(),
                                  true, 
                                  new CryptoPP::PK_DecryptorFilter(rng, decryptor, 
                                                                   new CryptoPP::Redirector(sink)));
        return true;
    } catch (CryptoPP::Exception& e) {
        this->_AESkey.CleanNew(0);
        return false;
    }
}

// get public key convert to array of 160 bytes
std::array<uint8_t, 160> CryptoManager::get_public_key(){
    std::array<uint8_t, 160> key = {0};
    std::string tmp;
    CryptoPP::StringSink sink(tmp);
    _publicKey.DEREncode(sink); 

    size_t copy_size = std::min(tmp.size(), key.size()); 
    std::memcpy(key.data(), tmp.data(), copy_size); // copy only the first 160 bytes
    return key;
}

std::string CryptoManager::get_Private_Key()
{
    std::string private_key;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(private_key), false);
    _privateKey.DEREncode(encoder);
    encoder.MessageEnd();
    return private_key;
}




