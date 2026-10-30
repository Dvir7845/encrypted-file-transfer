#include <iostream>
#include <stdexcept>
#include "connect.hpp"

int main()
{
    std::cout << "client start" << std::endl;

    try
    {
        Connect connect;
        std::cout << "connect created" << std::endl;

        if (connect.is_first_connection())
        {
            std::cout << "try to register" << std::endl;
            connect.register_user();
            std::cout << "try to send key" << std::endl;
            connect.send_rsa_key();
        }
        else
        {
            std::cout << "try to login" << std::endl;
            connect.login();
        }

        std::cout << "try to send file" << std::endl;
        connect.send_file();

        std::cout << "finish" << std::endl;
    }
    catch (const std::exception &e)
    {
        std::cout << e.what() << std::endl;
        return 1;
    }

    return 0;
}