#include "Protocol.hpp"
#include <array>
#include <string>
#include <vector>
#include <cstdint>
#include <iostream>

///////////////request constructors////////////

// constructor for  send key
Request::Request(std::string id, uint8_t version, Code code,
                 std::string name, std::array<uint8_t, KEY_LEN> public_key)
{
    push_hex(id);
    vec_request.push_back(version);
    push((uint16_t)code);
    uint32_t payload_size = NAME_LEN + KEY_LEN;
    push(payload_size);
    push(name);
    vec_request.insert(vec_request.end(), public_key.begin(), public_key.end());
}

// constructor for register login and crc request
Request::Request(std::string id, uint8_t version, Code code, std::string name)
{
    push_hex(id);
    vec_request.push_back(version);
    push((uint16_t)code);
    uint32_t payload_size = NAME_LEN;
    push(payload_size);
    push(name);
}
// constructor for send file
Request::Request(std::string id, uint8_t version, Code code, uint32_t content_size,
                 uint32_t orig_file_size, uint16_t packet_number,
                 uint16_t total_packets, std::string file_name,
                 std::vector<uint8_t> file_content)
{
    push_hex(id);
    vec_request.push_back(version);
    push((uint16_t)code);
    uint32_t payload_size = SEND_FILE_LEN + NAME_LEN + file_content.size();
    push(payload_size);
    push(content_size);
    push(orig_file_size);
    push(packet_number);
    push(total_packets);
    push(file_name);
    vec_request.insert(vec_request.end(), file_content.begin(), file_content.end());
}

///////////helper functions////////
void Request::push(uint32_t push32)
{
    vec_request.push_back(push32 & 0xFF);
    vec_request.push_back((push32 >> 8) & 0xFF);
    vec_request.push_back((push32 >> 16) & 0xFF);
    vec_request.push_back((push32 >> 24) & 0xFF);
}

void Request::push(uint16_t push16)
{
    vec_request.push_back(push16 & 0xFF);
    vec_request.push_back((push16 >> 8) & 0xFF);
}

void Request::push(std::string name)
{
    if (name.length() >= NAME_LEN) // check if name is too long
        throw std::runtime_error("name too long");
    for (size_t i = 0; i < NAME_LEN ; i++)
    {
        if (i < name.length())
            vec_request.push_back(name[i]);
        else
            vec_request.push_back(0); // padding
    }
}

void Request::push(std::vector<uint8_t> file_content)
{
    vec_request.insert(vec_request.end(), file_content.begin(), file_content.end());
}

void Request::push_hex(std::string hex_id)
{
    for (size_t i = 0; i < 32; i += 2)
    {
        std::string byte_str = hex_id.substr(i, 2);
        uint8_t byte = std::strtol(byte_str.c_str(), nullptr, 16);
        vec_request.push_back(byte);
    }
}

std::vector<uint8_t> Request::get_request()
{
    return vec_request;
}

///////////////////responze constructor //////////

Response::Response(std::vector<uint8_t> &buf)
{
    // read header
    if (buf.size() < 7)
        throw std::out_of_range("Invalid response size");
    this->version = buf[0];
    pop(this->code, 1, buf);
    pop(this->payload_size, 3, buf);

    // read payload
    switch ((Code)code)
    {
    case Code::SUCCESS_REGISTER:
        pop_hex(this->id, 7, buf);
        break;
    case Code::FAIL_REGISTER: // no payload
        break;
    case Code::SEND_AES_KEY:
        pop_hex(this->id, 7, buf);
        if (this->payload_size < 16) // to prevent buffer overflow
            throw std::out_of_range("Invalid response size");
        pop(this->aes_key, 23, buf, this->payload_size - 16);
        break;
    case Code::RECEIVE_FILE:
        pop_hex(this->id, 7, buf);
        pop(this->content_size, 23, buf);
        pop(this->file_name, 27, buf);
        pop(this->Cksum, 27 + NAME_LEN, buf);
        break;
    case Code::MESSAGE_RECEIVED:
        pop_hex(this->id, 7, buf);
        break;
    case Code::LOGIN_SUCCESS:
        pop_hex(this->id, 7, buf);
        if (this->payload_size < 16) // to prevent buffer overflow
            throw std::out_of_range("Invalid response size");
        pop(this->aes_key, 23, buf, this->payload_size - 16);
        break;
    case Code::LOGIN_FAIL:
        pop_hex(this->id, 7, buf);
        break;
    case Code::GENERAL_ERROR: // no payload
        break;
    default:
        break;
    }
}

/////////////helper functions////////
void Response::pop(uint32_t &pop32, size_t offset, std::vector<uint8_t> &buf)
{
    if (buf.size() < offset + 4)
        throw std::out_of_range("responze too short ");
    pop32 = static_cast<uint32_t>(buf[offset]) |
            (static_cast<uint32_t>(buf[offset + 1]) << 8) |
            (static_cast<uint32_t>(buf[offset + 2]) << 16) |
            (static_cast<uint32_t>(buf[offset + 3]) << 24);
}

void Response::pop(uint16_t &pop16, size_t offset, std::vector<uint8_t> &buf)
{
    if (buf.size() < offset + 2)
        throw std::out_of_range("responze too short ");
    pop16 = static_cast<uint16_t>(buf[offset]) |
            (static_cast<uint16_t>(buf[offset + 1]) << 8);
}

void Response::pop(std::vector<uint8_t> &vec,
                   size_t offset, std::vector<uint8_t> &buf, size_t len)
{
    if (buf.size() < offset + len)
        throw std::out_of_range("responze too short ");
    vec.assign(buf.begin() + offset, buf.begin() + offset + len);
}

void Response::pop(std::string &pop_str, size_t offset, std::vector<uint8_t> &buf)
{
    if (buf.size() < offset + NAME_LEN)
        throw std::out_of_range("responze too short ");
    for (size_t i = 0; i < NAME_LEN; i++)
    {
        if (buf[offset + i] == '\0')
            break;
        pop_str.push_back(buf[offset + i]);
    }
}

void Response::pop_hex(std::string &hex_id, size_t offset, std::vector<uint8_t> &buf)
{
    if (buf.size() < offset + 16)
        throw std::out_of_range("responze too short ");
    char hex[3];
    hex_id.clear();
    for (size_t i = 0; i < 16; i++)
    {
        snprintf(hex, sizeof(hex), "%02x", buf[offset + i]);
        hex_id.append(hex);
    }
}

////////////// getters ////////////
Code Response::get_code()
{
    return (Code)code;
}

std::string Response::get_id()
{
    return id;
}

std::vector<uint8_t> Response::get_aes_key()
{
    return aes_key;
}

uint32_t Response::get_cksum() const
{
    return this->Cksum;
}

uint32_t Response::get_content_size() const
{
    return this->content_size;
}
