#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>

enum class Code : uint16_t
{
    // requests
    REGISTER = 825,
    SEND_RSA_KEY = 826,
    LOGIN = 827,
    SEND_FILE = 828,
    CORRECT_CRC = 900,
    INCORRECT_CRC = 901,
    INCORRECT_CRC_4 = 902,
    // responses
    SUCCESS_REGISTER = 1600,
    FAIL_REGISTER = 1601,
    SEND_AES_KEY = 1602,
    RECEIVE_FILE = 1603,
    MESSAGE_RECEIVED = 1604,
    LOGIN_SUCCESS = 1605,
    LOGIN_FAIL = 1606,
    GENERAL_ERROR = 1607
};

const size_t NAME_LEN = 255;
const size_t KEY_LEN = 160;
const size_t SEND_FILE_LEN = 12;

class Request
{
public:
    Request(std::string id, uint8_t version, Code code, std::string name,
            std::array<uint8_t, KEY_LEN> public_key );
    
    Request(std::string id, uint8_t version, Code code, std::string name);
    
    Request(std::string id, uint8_t version, Code code,
            uint32_t content_size, uint32_t orig_file_size, uint16_t packet_number,
            uint16_t total_packets, std::string file_name,
            std::vector<uint8_t> file_content);


    std::vector<uint8_t> get_request();
    

private:
    std::vector<uint8_t> vec_request;
    void push(uint16_t push16);
    void push(uint32_t push32);
    void push(std::string name);
    void push(std::vector<uint8_t> file_content);
    void push_hex(std::string hex_id);
};

class Response
{
public:
    Response(std::vector<uint8_t> &buf);
    Code get_code();
    std::string get_id();
    std::vector<uint8_t> get_aes_key();
    uint32_t get_content_size() const;
    std::string get_file_name();
    uint32_t get_cksum() const;
    
    

private:
    uint8_t version;
    uint16_t code;
    uint32_t payload_size;
    std::string id;
    std::vector<uint8_t> aes_key;
    uint32_t content_size;
    std::string file_name;
    uint32_t Cksum;

    void pop(uint16_t &pop16, size_t offset, std::vector<uint8_t> &buf);
    void pop(uint32_t &pop32, size_t offset, std::vector<uint8_t> &buf);
    void pop(std::string &pop_str, size_t offset, std::vector<uint8_t> &buf);
    void pop(std::vector<uint8_t> &pop_vec, size_t offset,
             std::vector<uint8_t> &buf, size_t len);
    void pop_hex(std::string &pop_str, size_t offset, std::vector<uint8_t> &buf);
             

};

#endif
