#include "TerClient.h"

TerClient* TerClient::m_Instance = nullptr;

TerClient::TerClient()
	:m_Pool(NULL), m_ClientHeat(0)
{
	m_Instance = this;
	m_Token = "";

	m_Listener = Create_HP_TcpPackClientListener();
	m_pClient  = Create_HP_TcpPackClient(m_Listener);

	//4096kb
	HP_TcpPackClient_SetMaxPackSize(m_pClient, 0x3FFFFF);
	HP_Set_FN_Client_OnReceive(m_Listener, OnReceive);
	HP_Set_FN_Client_OnClose(m_Listener, OnClose);


}


TerClient::~TerClient()
{

}

TerClient* TerClient::GetInstance()
{
	return m_Instance;
}

BOOL TerClient::ConnectSrv(std::string ip, int port, USHORT pack_flag, int ver,ULONG syncTimeOut)
{

	VMProtectBegin(__FUNCTION__);

	//包头标识
	HP_TcpPackClient_SetPackHeaderFlag(m_pClient, pack_flag);

	//版本
	m_ClientVer = ver;
	//超时时间 
	m_Timeout = syncTimeOut;
	//创建事件
	m_hEvent = CreateEventA(NULL, FALSE, TRUE, /*"SAGA_Event_Client"*/NULL);
	ResetEvent(m_hEvent);

	BOOL bResult = HP_Client_Start(m_pClient,ip.c_str(), port,FALSE);

	VMProtectEnd();

	return bResult;
}

void TerClient::SetPackCallBack(mfn_CallBackHandleC mfn_OnClose, mfn_CallBackHandleC mfn_OnRecv)
{
	m_OnClose = mfn_OnClose;
	m_OnRecv  = mfn_OnRecv;
}

BOOL TerClient::SendVerCheck()
{
	BOOL bResult = FALSE;

	int PackSize = 1024;

	PackWriter Pack = PackWriter(PackSize);

	//版本验证
	Pack.WriteShort(TERI_IDX::TERI_IDX_VER);

	//软件版本号
	Pack.WriteInt(m_ClientVer);

	//判断状态码
	if (WaitEvent(Pack) && m_ClientMsg == TERI_CLIENT_MSG::TERI_CL_MSG_SUCCEED_VER)
	{
		//验证成功
		bResult = TRUE;
	}
	return bResult;
}

std::string TerClient::CalcMd5(BYTE* Input, int Size) 
{
	VMProtectBegin(__FUNCTION__);

	char md[33];

	MD5_CTX md5;

	MD5_Init(&md5);

	MD5_Update(&md5, (unsigned char*)Input, Size);

	MD5_Final((unsigned char*)md, &md5);

	char output[33] = { "" };

	for (int i = 0; i < 16; i++)
	{
		wsprintfA((output + (i * 2)), "%02x", (char)md[i] & 0x0ff);
	}
	std::string Result = output;

	VMProtectEnd();
	return Result;
}

BOOL TerClient::Stop()
{
	return HP_Client_Stop(m_pClient);
}

EnHandleResult TerClient::OnReceive(HP_Client pSender, HP_CONNID dwConnID, const BYTE* pData, int iLength)
{
	if (iLength > 0x4)
	{
		PackReader	Pack = PackReader((BYTE*)pData, iLength);

		if (Pack.ReadChar() != 0x55)
		{
			return HR_ERROR;
		}
		int PackSeq = Pack.ReadChar();

		if (PackSeq != 0x23)
		{
			return HR_ERROR;
		}

		//检查线程池是否启动.如果没有启动则启动
		if (!TerClient::GetInstance()->StartThreadPool())
		{
			TerClient::GetInstance()->MessageRecvHand(TERI_DISCT_START_POOL);

			return HR_ERROR;
		}
		HP_LPTSocketTask Task = Create_HP_SocketTaskObj(Task_ClientRecvThreadPool, pSender, dwConnID, pData, iLength, TBT_COPY, 0, 0);

		if (!HP_ThreadPool_Submit_Task(TerClient::GetInstance()->GetThreadPool(), Task, INFINITE))
		{
			Destroy_HP_SocketTaskObj(Task);

			return HR_ERROR;
		}

	}

	return  HR_OK;
}

EnHandleResult TerClient::OnClose(HP_Client pSender, HP_CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{

	//通知回调.连接已关闭
	PackWriter Pack = PackWriter(1024);
	//连接ID
	Pack.WriteInt(dwConnID);
	//断开类型
	Pack.WriteInt(enOperation);
	//错误代码
	Pack.WriteInt(iErrorCode);

	return TerClient::GetInstance()->CallBackOnClose(Pack.GetBytes(), Pack.GetBytesLength());
}

VOID __HP_CALL TerClient::Task_ClientRecvThreadPool(TSocketTask* pTask)
{
	TerClient::GetInstance()->AnalysePack(pTask);
}
void TerClient::MessageRecvHand(TERI_DISONNECT_TYPE DisconnectType)
{
	VMProtectBegin(__FUNCTION__);

	//通知回调函数
	PackWriter Packc = PackWriter(1024);

	//消息类型_断线
	Packc.WriteShort(TERI_IDX::TERI_IDX_DISCONNECT);

	//断开连接类型
	Packc.WriteInt(DisconnectType);

	m_OnRecv(Packc.GetBytes(), Packc.GetBytesLength());

	VMProtectEnd();
}

HP_ThreadPool TerClient::GetThreadPool()
{
	return m_Pool;
}

BOOL TerClient::CheckClientHeatTimeOut()
{
	BOOL	bResult = (GetTimeStamp() - m_ClientHeat <= 30 * 1000);

	//通知回调函数
	PackWriter Packc = PackWriter(1024);

	Packc.WriteShort(TERI_IDX::TERI_IDX_CL_HEAR_CHECK);

	//状态
	Packc.WriteInt(bResult);

	//客户端当前心跳戳
	Packc.WriteULong64(m_ClientHeat);

	if (m_OnRecv(Packc.GetBytes(), Packc.GetBytesLength()) == HR_ERROR)
	{
		Stop();
	}
	return bResult;
}

BOOL TerClient::SendClientInfo(DWORD dwProcessId, std::string AppName, std::string AppPath, std::string AppLine, ULONG64 StartTime)
{
	BOOL bResult = FALSE;

	int PackSize = 1024+ AppName.length()+ AppPath.length() + AppLine.length();

	PackWriter Pack = PackWriter(PackSize);

	//客户端信息
	Pack.WriteShort(TERI_IDX::TERI_IDX_CLINFO);

	//token
	Pack.WriteString(m_Token);

	Pack.WriteInt(dwProcessId);
	Pack.WriteString(AppName);
	Pack.WriteString(AppPath);
	Pack.WriteString(AppLine);

	if (!StartTime)
	{
		//如果为0 就是当前时间戳
		StartTime = GetTimeStamp();
	}

	Pack.WriteULong64(StartTime);


	//判断状态码
	if (WaitEvent(Pack) && m_ClientMsg == TERI_CLIENT_MSG::TERI_CL_MSG_SUCCEED_CLINFO)
	{
		//发送成功
		bResult = TRUE;
	}
	return bResult;
}

BOOL TerClient::SendGameUserInfo(std::string user, std::string password, std::string game_reg, std::string player_name, ULONG64 Lv, std::string info)
{
	BOOL bResult = FALSE;

	int PackSize = 1024 + user.length() + password.length() + game_reg.length() + player_name.length() + info.length();

	PackWriter Pack = PackWriter(PackSize);

	//发送游戏账号信息
	Pack.WriteShort(TERI_IDX::TERI_IDX_GAME_USER_INFO);

	//token
	Pack.WriteString(m_Token);

	Pack.WriteString(user);
	Pack.WriteString(password);
	Pack.WriteString(game_reg);
	Pack.WriteString(player_name);
	Pack.WriteULong64(Lv);
	Pack.WriteString(info);

	//判断状态码
	if (WaitEvent(Pack) && m_ClientMsg == TERI_CLIENT_MSG::TERI_CL_MSG_SUCCEED_GAMEINFO)
	{
		//发送成功
		bResult = TRUE;
	}
	return bResult;
}

BOOL TerClient::SendServerPackMessage(PackWriter& Pack)
{
	BOOL bResult = FALSE;



	PackWriter Packc = PackWriter(1024 + Pack.GetBytesLength());

	//发送自定义封包
	Packc.WriteShort(TERI_IDX::TERI_IDX_CLT_PACK);

	//token
	Packc.WriteString(m_Token);

	Packc.WriteBytes(Pack.GetBytes(), Pack.GetBytesLength());
	

	if (WaitEvent(Packc))
	{
		//发送成功
		bResult = TRUE;
	}
	return bResult;
}

void TerClient::AnalysePack(TSocketTask* pTask)
{
	VMProtectBegin(__FUNCTION__);

	PackReader	Pack = PackReader((BYTE*)pTask->buf, pTask->bufLen);

	Pack.SetIndex(2);

	//去掉头部标识
	PackWriter Recv = PackWriter(Pack.GetSize() - Pack.GetIndex());
	//AES解密
	AesEncrypt(Pack, Recv, AES_DECRYPT);

	TerClient* TeririPoint = TerClient::GetInstance();

	//判断MD5
	Pack = PackReader((BYTE*)Recv.GetBytes(), Recv.GetSize());

	char* cur_md5 = Pack.ReadStr();

	std::string src_md5 = TeririPoint->CalcMd5(Pack.GetOffsetBuffer(), Pack.GetBytesAvailable());

	if (lstrcmpA(cur_md5, src_md5.c_str()) != 0)
	{
		//MD5校验失败-通知回调消息-断开连接
		TeririPoint->MessageRecvHand(TERI_DISONNECT_TYPE::TERI_DISCT_MD5);

		//停止服务
		TeririPoint->Stop();

		return;
	}


	//先通知回调
	EnHandleResult EnResult = m_OnRecv(Pack.GetOffsetBuffer(), Pack.GetBytesAvailable());

	if (EnResult == HR_OK)
	{
		int Index = Pack.ReadShort();

		if (Index > 255)
		{
			//MD5校验失败-通知回调消息-断开连接
			TeririPoint->MessageRecvHand(TERI_DISONNECT_TYPE::TERI_DISCT_FUN);
			//停止服务
			TeririPoint->Stop();

			return;
		}

		//功能选项
		switch (Index)
		{
		case TERI_IDX_VER:
			EnResult = TeririPoint->PackIndexVerCheck(Pack);
			break;
		case TERI_IDX_HEAR:
			EnResult = TeririPoint->PackIndexHeat(Pack);
			break;
		case TERI_IDX_SRV_PACK:
			EnResult = TeririPoint->PackIndexMessage(Pack);
			break;
		case TERI_IDX_CLINFO:
			EnResult = TeririPoint->PackIndexGameUserInfo(Pack);
			break;

		default:
			break;
		}

	}
	//停止通讯
	if (EnResult == HR_ERROR)
	{
		TeririPoint->Stop();

	}
	VMProtectEnd();

}

EnHandleResult TerClient::PackIndexVerCheck(PackReader& Pack)
{
	BYTE	Status = Pack.ReadChar();

	if (Status)
	{
		m_Token = Pack.ReadStr();

		m_ClientMsg = TERI_CL_MSG_SUCCEED_VER;

		//启动心跳线程
		std::thread th(&TerClient::ClientHeartThread, this);
		th.detach();


		//再次通知回调版本验证成功_可以做一些初始化的事情
		PackWriter CPack = PackWriter(1024);
		CPack.WriteShort(TERI_IDX_VER);
		CPack.WriteByte(2);
		m_OnRecv(CPack.GetBytes(), CPack.GetSize());
	}

	SetEvent(m_hEvent);

	return HR_OK;
}



EnHandleResult TerClient::PackIndexHeat(PackReader& Pack)
{

	BYTE	Status = Pack.ReadChar();

	if (Status)
	{
		m_ClientHeat = Pack.ReadLong64();
	}

	return HR_OK;
}

void TerClient::ClientSendTask(PackWriter Pack, std::promise<int>& promiseObj)
{
	PackWriter SendPack;

	SendPack.HasPtr(Pack.GetBytesLength() + 1024);

	SendPack.WriteByte(0x55);
	SendPack.WriteByte(0x23);

	int AesPackSize = 0;

	std::string str_curMd5 = CalcMd5(Pack.GetBytes(), Pack.GetBytesLength());

	SendPack.WriteString(str_curMd5);

	SendPack.WriteBytes(Pack.GetBytes(), Pack.GetBytesLength());

	AesPackSize =SendPack.GetBytesLength() - 2;



	// 设置加密key
	AES_KEY aes;
	const unsigned char key[AES_BLOCK_SIZE] = { 0xB2, 0xC3, 0x21, 0x14, 0x22, 0x32, 0xA3, 0xC3, 0x03, 0x03, 0x33, 0x43, 0x33, 0xA1, 0xB2, 0xC3 };
	unsigned char iv[AES_BLOCK_SIZE] = { 0x22, 0x23, 0x31, 0x34, 0x42, 0x42, 0x52, 0x52, 0x62, 0x61, 0x73, 0x74, 0x83, 0x81, 0x02, 0x03 };
	AES_set_encrypt_key(key, 128, &aes);

	//AES大小为   Send包 - 2 的大小
	PackWriter PackAes = PackWriter(AesPackSize);

	//加密
	int num = 0;
	const unsigned char* in = (SendPack.GetBytes() + 2);
	unsigned char* out = PackAes.GetBytes();
	AES_cfb128_encrypt(in, out, PackAes.GetSize(), &aes, iv, &num, AES_ENCRYPT);



	//重新定位 Offset
	SendPack.SetOffset(2);

	//重新写入加密
	SendPack.WriteBytes(PackAes.GetBytes(), PackAes.GetSize());


	
	BOOL bResult = HP_Client_Send(m_pClient,SendPack.GetBytes(), SendPack.GetBytesLength());

	promiseObj.set_value(bResult);

}

void TerClient::ClientHeartThread()
{

	PackWriter Pack = PackWriter(1024);
	
	while (true)
	{

		Pack.Clear();

		//心跳
		Pack.WriteShort(TERI_IDX::TERI_IDX_HEAR);

		//Token
		Pack.WriteString(m_Token);

		Pack.WriteULong64(GetTimeStamp());

		std::promise<int> promiseObj;
		std::future<int> futureObj = promiseObj.get_future();
		std::thread th(&TerClient::ClientSendTask, this, Pack, std::ref(promiseObj));
		th.join();
	
		Sleep(3 * 1000);

		CheckClientHeatTimeOut();

	}
}

ULONG64 TerClient::GetTimeStamp()
{
	SYSTEMTIME tmSys;
	GetLocalTime(&tmSys);

	time_t curtime;

	time(&curtime);

	__int64 tmDst = __int64(curtime) * 1000 + tmSys.wMilliseconds;

	return tmDst;
}

void TerClient::AesEncrypt(PackReader& in, PackWriter& out, int inc)
{
	//AES 秘钥 初始化

	AES_KEY aes;

	const unsigned char key[AES_BLOCK_SIZE] = { 0xB2, 0xC3, 0x21, 0x14, 0x22, 0x32, 0xA3, 0xC3, 0x03, 0x03, 0x33, 0x43, 0x33, 0xA1, 0xB2, 0xC3 };

	unsigned char iv[AES_BLOCK_SIZE] = { 0x22, 0x23, 0x31, 0x34, 0x42, 0x42, 0x52, 0x52, 0x62, 0x61, 0x73, 0x74, 0x83, 0x81, 0x02, 0x03 };

	AES_set_encrypt_key(key, 128, &aes);

	int num = 0;

	AES_cfb128_encrypt(in.GetOffsetBuffer(), out.GetBytes(), out.GetSize(), &aes, iv, &num, inc);
}

BOOL TerClient::WaitEvent(PackWriter Pack)
{
	BOOL bResult = FALSE;


	std::promise<int> promiseObj;
	std::future<int> futureObj = promiseObj.get_future();
	std::thread th(&TerClient::ClientSendTask, this, Pack, std::ref(promiseObj));
	th.join();

	if (!futureObj.get())
	{
		//发送数据失败
		m_ClientMsg = TERI_CLIENT_MSG::TERI_CL_MSG_ER_SEND;
		return FALSE;
	}
	//重置
	ResetEvent(m_hEvent);

	DWORD dwResult = WaitForSingleObject(m_hEvent, m_Timeout); //等待事件

	switch (dwResult)
	{
	case WAIT_OBJECT_0:
		bResult = TRUE;
		break;
	case WAIT_TIMEOUT:
		m_ClientMsg = TERI_CLIENT_MSG::TERI_CL_MSG_TIMEOUT;
		bResult = FALSE;
		break;
	case WAIT_ABANDONED:
		m_ClientMsg = TERI_CLIENT_MSG::TERI_CL_MSG_ER_FUN;
		bResult = FALSE;
		break;
	default:
		bResult = FALSE;
		break;
	}
	return bResult;
}


EnHandleResult TerClient::CallBackOnClose(BYTE* buffer, int Size)
{
	return m_OnClose(buffer, Size);
}

BOOL TerClient::StartThreadPool()
{
	if (!m_Pool)
	{
		//创建线程池
		m_Pool = Create_HP_ThreadPool();
	}


	if (!HP_ThreadPool_HasStarted(m_Pool))
	{
		//线程池启动
		if (!HP_ThreadPool_Start(m_Pool, 0, 0, TRP_CALL_FAIL, 0))
		{
			m_ErrorCode = SYS_GetLastError();
			return FALSE;
		}

	}
	return TRUE;
}

EnHandleResult TerClient::PackIndexMessage(PackReader& Pack)
{
	//处理个J8
	return HR_OK;
}

EnHandleResult TerClient::PackIndexGameUserInfo(PackReader& Pack)
{

	BYTE	Status = Pack.ReadChar();

	if (Status)
	{
		m_ClientMsg = TERI_CL_MSG_SUCCEED_GAMEINFO;

	}

	SetEvent(m_hEvent);

	return HR_OK;
}
