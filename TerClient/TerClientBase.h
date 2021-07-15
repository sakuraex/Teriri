#pragma once
#include <AntiCpxBase.h>
#include <PackReader.h>
#include <PackWrite.h>


//AES 库
#include <openssl\aes.h>
#include <openssl\md5.h>
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")




//HP 库  DLL必须用4C.h C调用.  C++的智能指针在DLL下初始化有问题.具体原因我也不知道
#include <HPSocket4C.h>
//#include <SocketInterface.h>
#pragma comment(lib,"HPSocket4C.lib")

//其他设置
//#pragma execution_character_set("utf-8")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")

//STL
#include <map>
#include <mutex>
#include <future>      //std::future std::promise
#include <utility>     //std::ref
#ifndef _LIB
#pragma comment(lib,"TerClient.lib")

#endif