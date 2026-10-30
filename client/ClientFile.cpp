#include "ClientFile.hpp"
#include "cksum.hpp"

#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>

const size_t MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB

ClientFile::ClientFile(const std::string &file_path)
{
    this->file_name = extract_file_name(file_path);
    this->file_path = file_path;
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        throw std::runtime_error("Error opening file of client file: " + file_name);
    std::streamsize size = file.tellg();
    if (size == -1)
        throw std::runtime_error("Error reading file of client file: " + file_name);
    if (size > MAX_FILE_SIZE) // prevent crash if file is too large for memory
        throw std::runtime_error("File of client file is too large: " + file_name);
    this->orig_file_size = static_cast<uint32_t>(size);
    file.seekg(0, std::ios::beg);
    this->file_content.resize(this->orig_file_size);
    if (this->orig_file_size > 0)
        if (!file.read(reinterpret_cast<char *>(this->file_content.data()),
                       this->orig_file_size))
            throw std::runtime_error("Failed to read file content: " + file_name);
    // calculate cksum
    this->cksum = memcrc(const_cast < char * > (reinterpret_cast<char *>(this->file_content.data())),
                         this->file_content.size());
}

// set encrypted file in packets and calculate total packets
void ClientFile::set_encrypted_file_content(std::vector<uint8_t> encrypted_file_content)
{
    this->encrypted_file_content = encrypted_file_content;
    this->content_size = encrypted_file_content.size();
    if(this->content_size == 0){ //empty file
        this->total_packets = 1;
        this->packets.push_back({});
        return;
    }
    this->total_packets = (this->content_size + PACKET_SIZE - 1) / PACKET_SIZE;
    for (size_t i = 0; i < this->content_size; i += PACKET_SIZE)
    {
        size_t current_chunk_size = std::min(static_cast<size_t>(PACKET_SIZE), this->content_size - i);
        
        std::vector<uint8_t> packet(
            this->encrypted_file_content.begin() + i,
            this->encrypted_file_content.begin() + i + current_chunk_size
        );
        this->packets.push_back(std::move(packet));
    }
}

///////////////getters////////////
uint32_t ClientFile::get_orig_size()
{
    return this->orig_file_size;
}

uint32_t ClientFile::get_content_size()
{
    return this->content_size;
}

uint16_t ClientFile::get_total_packets()
{
    return this->total_packets;
}

std::vector<uint8_t> ClientFile::get_packet(uint16_t packet_number)
{
    return this->packets[packet_number - 1];
}

std::string ClientFile::get_file_name()
{
    return this->file_name;
}

std::vector<uint8_t> ClientFile::get_file_content()
{
    return this->file_content;
}

uint32_t ClientFile::get_cksum()
{
    return this->cksum;
}


std::string ClientFile::extract_file_name(const std::string& file_path)
{
    size_t last_slash_pos = file_path.find_last_of("/\\");
    if (last_slash_pos == std::string::npos)
        return file_path;
    return file_path.substr(last_slash_pos + 1);
}