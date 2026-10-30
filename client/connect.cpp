#include "connect.hpp"
#include "Protocol.hpp"
#include "CryptoManager.hpp"
#include "ClientFile.hpp"
#include <winsock2.h>
#include <string>
#include <vector>
#include <array>
#include <iostream>
#include <fstream>
#include <filesystem>
Connect::Connect()
{
    std::cout << "start create connect" << std::endl;
    this->first_connection = not(read_meInfo()); //if the file is not exist, its the first connection
    create_socket();
    std::cout << "end create socket" << std::endl;
}

Connect::~Connect()
{
    closesocket(clientSocket);
    WSACleanup();
}

//////////////////PUBLIC//////////////////
void Connect::register_user()
{
    Request request(this->id, VERSION, Code::REGISTER, s_info.get_client());
    Response response = send_3_times(request);
    if (response.get_code() != Code::SUCCESS_REGISTER)
        throw std::runtime_error("register failed 3 times try again later");
    this->id = response.get_id();
    write_meInfo();
}

void Connect::login()
{
    Request request(this->id, VERSION, Code::LOGIN, s_info.get_client());
    Response response = send_3_times(request);
    if (response.get_code() != Code::LOGIN_SUCCESS)
        if (response.get_code() == Code::LOGIN_FAIL){
            register_user();
            send_rsa_key();
            return;
        }
        else
            throw std::runtime_error("login failed, server error");
    if(!crypto_manager.set_AES_key(response.get_aes_key())) // set the new AES key
        throw std::runtime_error("set AES key failed");
}

void Connect::send_rsa_key()
{
    std::array<uint8_t, 160> public_key = crypto_manager.get_public_key();
    Request request(this->id, VERSION, Code::SEND_RSA_KEY, s_info.get_client(), public_key);
    Response response = send_3_times(request);
    if (response.get_code() != Code::SEND_AES_KEY)
        throw std::runtime_error("send key failed");
    if(!crypto_manager.set_AES_key(response.get_aes_key()))
        throw std::runtime_error("set AES key failed");
}

void Connect::send_file()
{
    std::string file_path , file_name;
    while ((file_path = s_info.get_next_file()) != "")
    {
    ClientFile client_file(file_path);
    file_name = client_file.get_file_name();
    // encrypt file
    client_file.set_encrypted_file_content(crypto_manager.encrypt_file(
        client_file.get_file_content()));

    // send file
    size_t total_packets = client_file.get_total_packets();
    std::vector<uint8_t> packet;
    size_t total_error = 0,crc_fail = 0;
    while(crc_fail < MAX_TRY_TO_SEND)
    {
        for (size_t j = 0; j < total_packets; j++) // send file by packets
        {
            packet = client_file.get_packet(j + 1);
            Request request(this->id, VERSION, Code::SEND_FILE,
                            client_file.get_content_size(),
                            client_file.get_orig_size(),
                            j + 1, total_packets, file_name, packet);
            int n = sendAll(reinterpret_cast<const char *>(request.get_request().data()),
                               request.get_request().size());
            if (n < 0) // if fail to send all the packets
                throw std::runtime_error("sendAll failed to send request");
        }

        Response response = receive_response();
        if(response.get_code() == Code::GENERAL_ERROR){
            total_error++;
            std::cout << "server responded with an error" << std::endl;
            if (total_error == MAX_SERVER_ERROR)
                throw std::runtime_error("Fatal: server responded with an error while sending file"+file_name);
            continue; 
        }
        if (response.get_code() != Code::RECEIVE_FILE)
            throw std::runtime_error("Fatal: server responded with an error while sending file"+file_name);
        // check cksum and send incorrect crc if fail 3 times 
        // if 4 times fail, send incorrect crc 4 times 
        if (response.get_cksum() != client_file.get_cksum())
        {
            crc_fail++;
            Code code = (crc_fail == MAX_TRY_TO_SEND) ? Code::INCORRECT_CRC_4 : Code::INCORRECT_CRC;
            Request request(this->id, VERSION, code, file_name);
            if (code == Code::INCORRECT_CRC){ 
                int n = sendAll(reinterpret_cast<const char *>(request.get_request().data()),
                        request.get_request().size());
                        if (n < 0)
                            throw std::runtime_error("sendAll failed to send request");
            }
            else{ // send incorrect crc 4 times
                if (send_3_times(request).get_code() != Code::MESSAGE_RECEIVED)
                    throw std::runtime_error("Fatal: abort was not accepted by server while sending file"+file_name);
                throw std::runtime_error("Fatal: crc verification failed 4 times while sending file"+file_name);
            }
                
        }
        else{
            Request request(this->id, VERSION, Code::CORRECT_CRC, file_name);
            if (send_3_times(request).get_code() != Code::MESSAGE_RECEIVED)
                throw std::runtime_error("Fatal: crc confirmation was not accepted acknowledgement "+file_name);
            break; // success to send file
        }
    }
}
}

///////////////HELPERS//////////////////

void Connect::create_socket()
{
    std::cout << "Enter create_socket" << std::endl;
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0)
        throw std::runtime_error("WSAStartup failed with error: " +
                                 std::to_string(res));
    // Create a socket
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET)
    {
        WSACleanup();
        throw std::runtime_error("Socket creation failed with error: " +
                                 std::to_string(WSAGetLastError()));
    }
    // Connect to the server
    std::cout << "Connecting to " << s_info.get_ip() << ":" << s_info.get_port() << std::endl;
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(s_info.get_ip().c_str());
    serverAddr.sin_port = htons(std::stoi(s_info.get_port()));
    if (connect(clientSocket, (sockaddr *)&serverAddr,
                sizeof(serverAddr)) == SOCKET_ERROR)
    {
        std::cerr << "Connection failed with error: " << WSAGetLastError() << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        throw std::runtime_error("Connection failed with error: " +
                                 std::to_string(WSAGetLastError()));
    }
    std::cout << "Connected to the server" << std::endl;
    this->clientSocket = clientSocket;
}

// this function receive a response from the server
//first it receive the header and check the size of the payload
//then it receive the exact payload 
Response Connect::receive_response()
{
    std::vector<uint8_t> header(RESPONSE_HEADER_SIZE);
    recv_exact(header.data(), RESPONSE_HEADER_SIZE);

    uint32_t payload_size = static_cast<uint32_t>(header[3]) |
                           (static_cast<uint32_t>(header[4]) << 8) |
                           (static_cast<uint32_t>(header[5]) << 16) |
                           (static_cast<uint32_t>(header[6]) << 24);

    std::vector<uint8_t> full_response = std::move(header);
    if (payload_size > MAX_PAYLOAD_SIZE)
        throw std::runtime_error("payload size is too large");
    full_response.resize(RESPONSE_HEADER_SIZE + payload_size);

    if (payload_size > 0)
    {
        recv_exact(full_response.data() + RESPONSE_HEADER_SIZE, payload_size);
    }

    return Response(full_response);
}

// this function send a request to the server
//if the response is fail, it will send the request again 3 times
//after 3 times its will return the response even if its fail
Response Connect::send_3_times(Request &request)
{
    int n = sendAll(reinterpret_cast<const char *>(request.get_request().data()), request.get_request().size());
    if (n < 0)
        throw std::runtime_error("sendAll failed to send request");
    Response response = receive_response();
    Code code = response.get_code();
    // send 3 times if fail
    for (int i = 0; i < 2; i++)
    {
        if (code != Code::FAIL_REGISTER &&
            code != Code::GENERAL_ERROR &&
            code != Code::LOGIN_FAIL)
            return response; // sucess
        std::cout << "server responded with an error" << std::endl;
        std::cout << (int)code << std::endl;
        n =  sendAll(reinterpret_cast<const char *>(request.get_request().data()), request.get_request().size());
        if (n < 0)
            throw std::runtime_error("sendAll failed to send request");
        response = receive_response();
        code = response.get_code();
    }
    return response; // after sucssess or 3 times of fail
}

// this function write the name, id and private key to me.info file
void Connect::write_meInfo()
{
    std::filesystem::path me_info_path = Transfer_json::get_exe_dir() / "me.info";
    std::ofstream file(me_info_path);
    if (!file.is_open())
        throw std::runtime_error("Error opening file");
    file << s_info.get_client() << std::endl
         << id << std::endl
         << crypto_manager.get_Private_Key() << std::endl; 
    file.close();
}

// this function read the name and id  from me.info file
//if the function return false, it means that need to register
//(the private key read from the file priv.key in CryptoManager class)
bool Connect::read_meInfo()
{
    std::filesystem::path me_info_path = Transfer_json::get_exe_dir() / "me.info";
    std::ifstream file(me_info_path);
    if (!file.is_open())
        return false;
    std::string client_name;
    if (!std::getline(file, client_name) || !std::getline(file, this->id))
        throw std::runtime_error("invalid me.info");
    file.close();
    if (client_name.empty() || id.empty())
        throw std::runtime_error("me.info is empty");
    // remove \r from name and id
    if (client_name.back() == '\r')
        client_name.pop_back();
    if (this->id.back() == '\r')
        this->id.pop_back();
    if (client_name != s_info.get_client() )
        throw std::runtime_error("client name in me.info is not the same as the name in transfer.json");
    return true;
}

bool Connect::is_first_connection()
{
    return this->first_connection;
}

// this function receive a exact number of bytes from the server
//if the function receive less than the number of bytes, it will throw an error
void Connect::recv_exact(uint8_t* buffer, size_t len)
{
    size_t total_received = 0;
    while (total_received < len)
    {
        int bytes = recv(clientSocket, 
                         reinterpret_cast<char*>(buffer + total_received), 
                         static_cast<int>(len - total_received), 
                         0);
        if (bytes <= 0)
            throw std::runtime_error("Server disconnected or network error");
        total_received += bytes;
    }
}


int Connect::sendAll(const char* buf, int len){
    int total_sent = 0;
    int left = len;
    while(total_sent<len){
        int n = send(clientSocket, buf + total_sent, left,0);
        if(n <= 0)
            return -1;
        total_sent += n;
        left -= n;
    }
    return 0;
}


