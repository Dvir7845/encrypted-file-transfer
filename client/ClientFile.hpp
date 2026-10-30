#ifndef CLIENTFILE_H
#define CLIENTFILE_H

#include <string>
#include <vector>
#include <cstdint>

const size_t PACKET_SIZE = 32 * 1024; // 32 KB

class ClientFile
{
public:
    ClientFile(const std::string& file_path);
    uint32_t get_orig_size();
    uint32_t get_content_size();
    uint16_t get_total_packets();
    std::vector<uint8_t> get_packet(uint16_t packet_number);
    std::string get_file_name();
    std::vector<uint8_t> get_file_content();
    uint32_t get_cksum();
    void set_encrypted_file_content(std::vector<uint8_t> encrypted_file_content);

private:
    std::string file_name;
    std::string file_path;
    std::vector<uint8_t> file_content;
    std::vector<uint8_t> encrypted_file_content ;
    uint32_t orig_file_size;
    uint32_t content_size;
    uint16_t total_packets ;
    std::vector<std::vector<uint8_t>> packets;
    uint32_t cksum;
    std::string extract_file_name(const std::string& file_path);
    };

#endif