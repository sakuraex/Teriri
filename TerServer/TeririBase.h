#pragma once

#include <AntiCpxBase.h>
#include <PackReader.h>
#include <PackWrite.h>



//AES ��
#include <openssl\aes.h>
#include <openssl\md5.h>
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")




//HP ��
#include <HPSocket.h>
#include <SocketInterface.h>
#pragma comment(lib,"HPSocket.lib")

//��������
//#pragma execution_character_set("utf-8")
#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")


//STL
#include <map>

#ifndef _LIB
#pragma comment(lib,"TerServer.lib")

#endif