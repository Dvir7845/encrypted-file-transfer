#ifndef CONNECT_H
#define CONNECT_H

#include <winsock2.h>
#include <string>
#include <vector>
#include <array>
#include <iostream>
#include <cstdint> 
#include <filesystem>
#include "Protocol.hpp"   
#include "CryptoManager.hpp"
#include "Transfer_json.hpp"

const int MAX_TRY_TO_SEND = 4;
const int MAX_SERVER_ERROR = 3;
const int RESPONSE_HEADER_SIZE = 7;
const int VERSION = 3;
const int MAX_PAYLOAD_SIZE = 279;

class Connect
{
public:
    Connect();
    ~Connect();
    void register_user();   
    void send_rsa_key();
    void login();
    void send_file(); 
    void correct_crc();
    void incorrect_crc();
    void incorrect_crc_4();
    Response receive_response();
    bool is_first_connection();
    void recv_exact(uint8_t *buf, size_t len);
private:
    bool first_connection = true;
    CryptoManager crypto_manager;
    Transfer_json s_info;
    std::string id = "00000000000000000000000000000000"; // 16 bytes
    std::vector<std::string> file_list;
    SOCKET clientSocket;
    void create_socket();
    Response send_3_times(Request &request);
    void write_meInfo();
    bool read_meInfo();
    int sendAll(const char *buf, int len);
    

};

#endif