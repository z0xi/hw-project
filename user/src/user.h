#ifndef __USER_H__
#define __USER_H__

#include <iostream>
#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <sstream>
#include <cstring>
#include <string>
#include "nlohmann/json.hpp"
//ifstraem
#include <fstream>
#include "ctcpserver.h"

class User
{
public:

    void decrypt(uint16_t* bufArray, int size);
};

#endif