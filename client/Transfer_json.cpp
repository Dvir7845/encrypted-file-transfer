#include "Transfer_json.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <stdexcept>
#include <winsock2.h>

Transfer_json::Transfer_json()
{
    std::filesystem::path transfer_json_path = Transfer_json::get_exe_dir() / "transfer.json";
    std::ifstream file(transfer_json_path, std::ios::binary | std::ios::ate);
    if (!file.is_open())
        throw std::runtime_error("Error opening file transfer.json");
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::string content;
    content.resize(size);
    file.read(&content[0], size);
    std::string server_info = extract_by_title(content, "server", '{', '}');
    extract_server_info(server_info);
    if (!check_port_and_ip())
        throw std::runtime_error("Invalid port or ip");
    std::string file_list_info = extract_by_title(content, "files", '[', ']');
    this->file_list = split_comma(file_list_info);
}



std::string Transfer_json::extract_by_title(const std::string buf,const std::string title,const char begin,const char end)
{
    size_t title_pos = buf.find(title);
    if (title_pos != std::string::npos){
        for (size_t i = title_pos + title.size(); i < buf.size(); i++){
            if (buf[i] == begin){
                size_t end_pos = buf.find(end,i+1);
                if (end_pos != std::string::npos){
                    return buf.substr(i + 1, end_pos - i - 1);
                }
            }
        }
    }
    throw std::runtime_error("Error extracting " + title);
}

std::string Transfer_json::trim(const std::string& str)
{
    const std::string to_trim = " \n\r\t\"";
    size_t first = str.find_first_not_of(to_trim);
    if (std::string::npos == first)
        return "";
    size_t last = str.find_last_not_of(to_trim);
    return str.substr(first, (last - first + 1));
}


// split comma separated string into vector of strings
// if there is a quote, the quote is not included in the string
std::vector<std::string> Transfer_json::split_comma(const std::string str)
{
    std::vector<std::string> result;
    std::string item = "";
    bool in_quotes = false;
    for (char c : str)
    {
        if (c == '"')
            in_quotes = !in_quotes;
        else if (c == ',' && !in_quotes)
        {
            std::string trimmed_item = trim(item);
            if (trimmed_item.empty())
                continue;
            result.push_back(trimmed_item);
            item = "";
        }
        else
            item += c;
    }
    if (!item.empty())
    {
        std::string trimmed_item = trim(item);
        if (!trimmed_item.empty())
        result.push_back(trimmed_item);
    }
    return result;
}

void Transfer_json::extract_server_info(const std::string& server_info)
{
    std::vector<std::string> server_info_list = split_comma(server_info);
    bool found_ip = false, found_port = false, found_name = false;
    for (std::string& item : server_info_list)
    {
        size_t colon_pos = item.find(':');
        if (colon_pos != std::string::npos)
        {
            std::string key = trim(item.substr(0, colon_pos));
            std::string value = trim(item.substr(colon_pos + 1));
            if (key == "ip")
            {
                if (found_ip)
                    throw std::runtime_error("Error reading server info: ip already found");
                found_ip = true;
                this->ip = value;
            }
            else if (key == "port")
            {
                if (found_port)
                    throw std::runtime_error("Error reading server info: port already found");
                found_port = true;
                this->port = value;
            }
            else if (key == "client")
            {
                if (found_name)
                    throw std::runtime_error("Error reading server info: client already found");
                if (value.size() > MAX_NAME_SIZE)
                    throw std::runtime_error("Error reading server info: client name too long");
                found_name = true;
                this->client = value;
            }
            else
                throw std::runtime_error("Error reading server info: unknown key " + key);
        }
    }
    if (!found_ip||!found_port||!found_name)
        throw std::runtime_error("Error reading server info: ip, port or client not found");
}

bool Transfer_json::check_port_and_ip()
{
    // check ip
    size_t count_dots = 0;
    std::string digits_between_dots = "";
    for (char &c : this->ip)
    {
        if (c == '\n' || c == '\r')
            break; // end of line
        if (c == '.')
            if (digits_between_dots == "") // no digits
                return false;
            else if (std::stoi(digits_between_dots) > MAX_IP || count_dots == 3)
                return false;
            else
            {
                count_dots++;
                digits_between_dots = "";
            }
        else // digit (trust extract_info)
            digits_between_dots += c;
    }
    if (digits_between_dots == "") // no digits
        return false;
    if (count_dots != 3 || std::stoi(digits_between_dots) > MAX_IP)
        return false;
    // check port
    if (this->port.empty())
        return false;
    int num_port = std::stoi(this->port);
    if (num_port < MIN_PORT || num_port > MAX_PORT)
        return false;
    return true;
}


////////////get functions//////////////////
std::string Transfer_json::get_ip()
{
    return this->ip;
}

std::string Transfer_json::get_port()
{
    return this->port;
}

std::string Transfer_json::get_client()
{
    return this->client;
}

std::string Transfer_json::get_next_file()
{
    if (this->index < this->file_list.size())
        return this->file_list[this->index++];
    return "";
}

// get the directory of the exe file for me.info
std::filesystem::path Transfer_json::get_exe_dir()
{
    wchar_t path[MAX_PATH] = {};
    DWORD size = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (size == 0|| size >= MAX_PATH)
        throw std::runtime_error("Error getting exe file path");
    return std::filesystem::path(path).parent_path();
}
        
        
        
    