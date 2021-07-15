// TeRiRiTestClient.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <TerClientBase.h>
#include <TerClient.h>
#pragma warning(disable:4099);
EnHandleResult WINAPI mfn_Recv(BYTE* buffer, int Size)
{

	AntiFileLog(__FUNCTION__);

	return HR_OK;
}
EnHandleResult WINAPI mfn_Close(BYTE* buffer, int Size)
{

	AntiFileLog(__FUNCTION__);

	return HR_OK;
}
int main()
{
  
	TerClient	TeririClient;

	TeririClient.SetPackCallBack(mfn_Close, mfn_Recv);

	TeririClient.ConnectSrv("127.0.0.1", 7008, 223, 1,0);

	TeririClient.SendVerCheck();



	//TCHAR szFileName[MAX_PATH + 1];
	//GetModuleFileName(NULL, szFileName, MAX_PATH);


	//char* szAppName = (strrchr(szFileName, '\\')) ? strrchr(szFileName, '\\') + 1 : szFileName;


	//TeririClient.SendClientInfo(GetCurrentProcessId(), szAppName, "", "", 0);


	getchar();
}

