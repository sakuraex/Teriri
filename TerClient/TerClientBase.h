#pragma once
#include <AntiCpxBase.h>
#include <PackReader.h>
#include <PackWrite.h>


//AES ��
#include <openssl\aes.h>
#include <openssl\md5.h>
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "Crypt32.lib")




//HP ��  DLL������4C.h C����.  C++������ָ����DLL�³�ʼ��������.����ԭ����Ҳ��֪��
#include <HPSocket4C.h>
//#include <SocketInterface.h>
#pragma comment(lib,"HPSocket4C.lib")

//��������
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