#ifndef TRANSFER_JSON_H
#define TRANSFER_JSON_H

#include <string>
#include <vector>
#include <filesystem>

const int MAX_PORT = 65535;
const int MIN_PORT = 1024;
const int MAX_IP = 255;
const int MAX_NAME_SIZE = 100;

class Transfer_json
{
public:
    Transfer_json();
    std::string get_ip();
    std::string get_port();
    std::string get_client();
    std::string get_next_file();
    static std::filesystem::path get_exe_dir();
private:
    std::string ip;
    std::string port;
    std::string client;
    std::vector <std::string> file_list;
    int index = 0;
    bool check_port_and_ip();
    void extract_server_info(const std::string& server_info);
    std::string  trim(const std::string& str);
    std::string extract_by_title(const std::string buf,const std::string title,const char begin,const char end);
    std::vector<std::string> split_comma(const std::string str);
    
};

#endif

