#include "TerServer.h"
#include <thread>
TeririServer* TeririServer::m_Instance = nullptr;


TeririServer::TeririServer()
	:m_Server(this)
{
	
	m_Instance = this;
}

TeririServer::~TeririServer()
{

}

TeririServer* TeririServer::TeririServer::GetInstance()
{
	return m_Instance;
}

BOOL TeririServer::StartSvr(int nPort, USHORT PackFlag, int Ver)
{
	VMProtectBegin(__FUNCTION__);

	//4096kb
	m_Server->SetMaxPackSize(0x3FFFFF);
	//包头标识
	m_Server->SetPackHeaderFlag(PackFlag);
	//创建线程池
	m_Pool = HP_Create_ThreadPool();
	//线程池启动
	m_Pool->Start();
	//版本
	m_ServerVer = Ver;
	//心跳超时时间 默认30秒
	m_HeartTimeout = 30 * 1000;

	BOOL bResult = m_Server->Start((LPCTSTR)"0.0.0.0", nPort);

	if (bResult)
	{
		//启动心跳线程
		std::thread th(&TeririServer::ThreadCheckHeatPack, this);
		th.detach();

	}
	VMProtectEnd();
	return bResult;
}

BOOL TeririServer::StopSvr()
{
	HP_Destroy_ThreadPool(m_Pool);

	return m_Server->Stop();
}

void TeririServer::SetPackCallBack(mfn_CallBackHandle OnAccept, mfn_CallBackHandle OnClose, mfn_CallBackHandle OnRecv)
{
	m_OnAccept = OnAccept;
	m_OnClose  = OnClose;
	m_OnRecv   = OnRecv;
}
EnHandleResult TeririServer::OnAccept(ITcpServer* pSender, CONNID dwConnID, SOCKET soClient)
{
	TCHAR szAddress[50];

	int iAddressLen = sizeof(szAddress) / sizeof(TCHAR);

	USHORT usPort;

	m_Server->GetRemoteAddress(dwConnID, szAddress, iAddressLen, usPort);

	//通知回调.有客户进入
	PackWriter Pack = PackWriter(1024);
	//IP地址
	Pack.WriteString(szAddress);
	//端口
	Pack.WriteInt(usPort);

	return m_OnAccept(dwConnID,Pack.GetBytes(), Pack.GetBytesLength());
}

EnHandleResult TeririServer::OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength)
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

		LPTSocketTask Task = HP_Create_SocketTaskObj(Task_ServerRecvThreadPool, pSender, dwConnID, pData, iLength);

		if (!m_Pool->Submit(Task))
		{
			HP_Destroy_SocketTaskObj(Task);

			return HR_ERROR;
		}
	}

	return  HR_OK;
}

std::string TeririServer::CrateToken(CONNID connID)
{
	std::string Value = std::to_string(connID) + std::to_string(GetTimeStamp());

	return CalcMd5((BYTE*)Value.c_str(), Value.length());
}

ULONG64 TeririServer::GetTimeStamp()
{
	SYSTEMTIME tmSys;

	GetLocalTime(&tmSys);

	time_t curtime;

	time(&curtime);

	__int64 tmDst = __int64(curtime) * 1000 + tmSys.wMilliseconds;

	return tmDst;
}

void TeririServer::AesEncrypt(PackReader& in, PackWriter& out, int inc)
{
	//AES 秘钥 初始化

	AES_KEY aes;

	const unsigned char key[AES_BLOCK_SIZE] = { 0xB2, 0xC3, 0x21, 0x14, 0x22, 0x32, 0xA3, 0xC3, 0x03, 0x03, 0x33, 0x43, 0x33, 0xA1, 0xB2, 0xC3 };

	unsigned char iv[AES_BLOCK_SIZE] = { 0x22, 0x23, 0x31, 0x34, 0x42, 0x42, 0x52, 0x52, 0x62, 0x61, 0x73, 0x74, 0x83, 0x81, 0x02, 0x03 };

	AES_set_encrypt_key(key, 128, &aes);

	int num = 0;

	AES_cfb128_encrypt(in.GetOffsetBuffer(), out.GetBytes(), out.GetSize(), &aes, iv, &num, inc);

}

VOID __HP_CALL TeririServer::Task_ServerRecvThreadPool(TSocketTask* pTask)
{
	TeririServer::GetInstance()->AnalysisPack(pTask);
}

VOID __HP_CALL TeririServer::Task_ServerSendThreadPool(TSocketTask* pTask)
{

	PackWriter	Pack = PackWriter(pTask->bufLen, "", (BYTE*)pTask->buf);

	TeririServer* hpManage = TeririServer::GetInstance();

	bool result = hpManage->ClientSendPack(pTask->connID, Pack);

	if (!result || pTask->wparam == HR_ERROR)
	{
		//踢掉用户
		hpManage->disconnectClient(pTask->connID);
	}
}
void TeririServer::disconnectClient(CONNID dwConnID)
{
	Sleep(250);

	m_Server->Disconnect(dwConnID);
}

void TeririServer::MessageRecvHand(CONNID connID, TERI_DISONNECT_TYPE DisconnectType)
{

	//通知回调函数
	PackWriter Packc = PackWriter(1024);

	//消息类型_断线
	Packc.WriteShort(TERI_IDX::TERI_IDX_DISCONNECT);

	//断开连接类型
	Packc.WriteInt(DisconnectType);

	OnRecvHand(connID,Packc.GetBytes(), Packc.GetBytesLength());

}

std::map<CONNID, PTAG_TERI_CLIENT_INFO>* TeririServer::GetMapClentInfo()
{
	return &m_MapToken;
}

std::string TeririServer::CalcMd5(BYTE* Input,int Size)
{
	VMProtectBegin(__FUNCTION__);

	char output1[33];

	MD5_CTX md5;

	MD5_Init(&md5);

	MD5_Update(&md5, (unsigned char*)Input, Size);

	MD5_Final((unsigned char*)output1, &md5);

	char OutPut[1024] = { 0 };

	for (int i = 0; i < 16; i++)
	{
		wsprintfA(((CHAR*)OutPut + (i * 2)), "%02x", (char)output1[i] & 0x0ff);
	}
	std::string Result = OutPut;

	VMProtectEnd();
	return Result;
}
bool TeririServer::ClientSendPack(CONNID dwConnID, PackWriter Pack)
{
	VMProtectBegin(__FUNCTION__);

	PackWriter SendPack;

	//PackSize + 头部两个字节 + MD5 大小

	SendPack.HasPtr(Pack.GetSize() + 2 + 33);

	SendPack.WriteByte(0x55);
	SendPack.WriteByte(0x23);

	int AesPackSize = 0;

	std::string  str_curMd5 = CalcMd5(Pack.GetBytes(), Pack.GetSize());

	SendPack.WriteString(str_curMd5);

	SendPack.WriteBytes(Pack.GetBytes(), Pack.GetSize());

	AesPackSize = str_curMd5.length() + 1 + Pack.GetSize();


	// 设置加密key
	AES_KEY aes;
	const unsigned char key[AES_BLOCK_SIZE] = { 0xB2, 0xC3, 0x21, 0x14, 0x22, 0x32, 0xA3, 0xC3, 0x03, 0x03, 0x33, 0x43, 0x33, 0xA1, 0xB2, 0xC3 };
	unsigned char iv[AES_BLOCK_SIZE] = { 0x22, 0x23, 0x31, 0x34, 0x42, 0x42, 0x52, 0x52, 0x62, 0x61, 0x73, 0x74, 0x83, 0x81, 0x02, 0x03 };
	AES_set_encrypt_key(key, 128, &aes); // 这里填写的128是bit位，128bit=(128/8)bytes=16bytes，这个换算和32bit对应int为内存指针的原理一样。

	//AES大小为   Send包 - 2 的大小
	PackWriter PackAes = PackWriter(SendPack.GetBytesLength() - 2);

	//加密
	int num = 0;
	const unsigned char* in = (SendPack.GetBytes() + 2);
	unsigned char* out = PackAes.GetBytes();
	AES_cfb128_encrypt(in, out, PackAes.GetSize(), &aes, iv, &num, AES_ENCRYPT);


	//重新定位 Offset
	SendPack.SetOffset(2);

	//重新写入加密
	SendPack.WriteBytes(PackAes.GetBytes(), PackAes.GetSize());


	VMProtectEnd();
	return m_Server->Send(dwConnID, SendPack.GetBytes(), SendPack.GetBytesLength());
}




EnHandleResult TeririServer::packIndexVerCheck(int Index, PackReader& Pack, CONNID connID)
{
	VMProtectBegin(__FUNCTION__);

	EnHandleResult Result = HR_OK;


	BYTE	Status = 0;

	//客户端版本号
	int client_ver = Pack.ReadInt();

	if (client_ver == m_ServerVer)
		Status = 1;


	//失败与成功-都要通知客户端
	PackWriter ClienPack = PackWriter(1024);

	ClienPack.WriteShort(Index);

	ClienPack.WriteByte(Status);

	//生成客户端令牌
	if (Status)
	{
		// 生成一段Token
		std::map<CONNID, PTAG_TERI_CLIENT_INFO>::iterator it;

		std::string token = CrateToken(connID);

		it = m_MapToken.find(connID);

		if (it == m_MapToken.end())
		{
			//没找到.连接ID 插入新的Token
			TERI_CLIENT_INFO* pInfo = new TERI_CLIENT_INFO(token, GetTimeStamp());

			m_MapToken.insert(std::pair<CONNID, PTAG_TERI_CLIENT_INFO>(connID, pInfo));
		}
		else
		{
			//如果找到了 那就改为新的Token
			m_MapToken[connID]->Token = token;

			/*
			*	一般情况下是不会找到的Key的.除非重复版本验证和超过了最大连接数量.
			*/
		}

		//令牌写入封包
		ClienPack.WriteString(token);
	}

	LPTSocketTask Task = HP_Create_SocketTaskObj(Task_ServerSendThreadPool, m_Server, connID, ClienPack.GetBytes(), ClienPack.GetBytesLength(), TBT_COPY, Result);

	if (!m_Pool->Submit(Task))
	{
		HP_Destroy_SocketTaskObj(Task);
	}

	VMProtectEnd();

	return Result;
}

EnHandleResult TeririServer::packIndexHeart(int Index, PackReader& Pack, CONNID connID)
{
	VMProtectBegin(__FUNCTION__);

	EnHandleResult Result = HR_OK;

	//心跳时间
	ULONG64 heat_time = Pack.ReadLong64();

	//修改心跳时间
	m_MapToken[connID]->Heart = heat_time;

	//返回给客户端心跳
	PackWriter ClienPack = PackWriter(1024);

	ClienPack.WriteShort(Index);

	ClienPack.WriteByte(1);

	ClienPack.WriteULong64(heat_time);

	LPTSocketTask Task = HP_Create_SocketTaskObj(Task_ServerSendThreadPool, m_Server, connID, ClienPack.GetBytes(), ClienPack.GetBytesLength(), TBT_COPY, Result);

	if (!m_Pool->Submit(Task))
	{
		HP_Destroy_SocketTaskObj(Task);
	}
	VMProtectEnd();

	return Result;
}

EnHandleResult TeririServer::packIndexClienInfo(int Index, PackReader& Pack, CONNID connID)
{
	VMProtectBegin(__FUNCTION__);

	EnHandleResult Result = HR_OK;

	//修改客户端信息
	m_MapToken[connID]->ProcessId = Pack.ReadInt();
	m_MapToken[connID]->ClientPath = Pack.ReadStr();
	m_MapToken[connID]->ClientName = Pack.ReadStr();
	m_MapToken[connID]->ClientLine = Pack.ReadStr();
	m_MapToken[connID]->ClientStartTime = Pack.ReadLong64();


	//返回给客户端
	PackWriter ClienPack = PackWriter(1024);

	ClienPack.WriteShort(Index);
	ClienPack.WriteByte(1);

	LPTSocketTask Task = HP_Create_SocketTaskObj(Task_ServerSendThreadPool, m_Server, connID, ClienPack.GetBytes(), ClienPack.GetBytesLength(), TBT_COPY, Result);

	if (!m_Pool->Submit(Task))
	{
		HP_Destroy_SocketTaskObj(Task);
	}
	VMProtectEnd();
	return Result;
}

EnHandleResult TeririServer::packIndexGameUserInfo(int Index, PackReader& Pack, CONNID connID)
{
	VMProtectBegin(__FUNCTION__);

	// 先通知回调函数
	EnHandleResult Result = HR_OK;

	//把发过来的游戏账号信息.通知回调函数.自己则不作任何处理.

	//返回给客户端
	PackWriter ClienPack = PackWriter(1024);

	ClienPack.WriteShort(Index);

	ClienPack.WriteByte(1);

	LPTSocketTask Task = HP_Create_SocketTaskObj(Task_ServerSendThreadPool, m_Server, connID, ClienPack.GetBytes(), ClienPack.GetBytesLength(), TBT_COPY, Result);

	if (!m_Pool->Submit(Task))
	{
		HP_Destroy_SocketTaskObj(Task);
	}

	VMProtectEnd();

	return Result;
}

EnHandleResult TeririServer::OnRecvHand(CONNID connID, BYTE* buffer, int Size)
{
	return m_OnRecv(connID,buffer, Size);
}

EnHandleResult TeririServer::OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode)
{

	// 删除绑定的客户端信息
	std::map<CONNID, PTAG_TERI_CLIENT_INFO>::iterator it;

	it = m_MapToken.find(dwConnID);

	if (it != m_MapToken.end())
	{
		//暂时不删除 因为线程不同步的原因.导致检测心跳线程那里有问题.
		//m_MapToken.erase(it);
		it->second->Token = "";
		it->second->Heart = 0;
		it->second->ProcessId = 0;

	}

	//通知回调.有客户离开
	PackWriter Pack = PackWriter(1024);
	//连接ID
	Pack.WriteInt(dwConnID);
	//断开类型
	Pack.WriteInt(enOperation);
	//错误代码
	Pack.WriteInt(iErrorCode);

	return m_OnClose(dwConnID,Pack.GetBytes(), Pack.GetBytesLength());
}

void TeririServer::ThreadCheckHeatPack()
{

	while (true)
	{
		Sleep(5 * 1000);		//五秒检测一次

		std::map<CONNID, PTAG_TERI_CLIENT_INFO>::iterator it = m_MapToken.begin();

		while (it != m_MapToken.end())
		{
			if (it->second->ProcessId == 0 && it->second->Token.empty())
			{
				//进程ID = 0 且 令牌为空
				it++;
				continue;
			}

			ULONG64 ulTimeHeat = GetTimeStamp();

			ULONG64 Value = abs((LONGLONG)(ulTimeHeat - it->second->Heart));

			PackWriter Packc = PackWriter(1024);

			//类型-心跳线程
			Packc.WriteShort(TERI_IDX_SRV_HEAR_THREAD);


			if (Value >= m_HeartTimeout)
			{
				//状态 0 = 异常
				Packc.WriteByte(0);
				//进程ID
				Packc.WriteInt(it->second->ProcessId);
				//进程名
				Packc.WriteString(it->second->ClientName);

			}
			else
			{
				//状态 1 = 正常
				Packc.WriteByte(1);
			}

			EnHandleResult Result =  OnRecvHand(it->first,Packc.GetBytes(), Packc.GetBytesLength());

			if (Result == HR_ERROR)
			{
				disconnectClient(it->first);
			}
			it++;
		}

	}

}


BOOL TeririServer::SendClientPackMessage(CONNID connID, PackWriter& Pack)
{

	PackWriter ClienPack = PackWriter(1024 + Pack.GetSize());

	ClienPack.WriteShort(TERI_IDX::TERI_IDX_SRV_PACK);

	ClienPack.WriteBytes(Pack.GetBytes(), Pack.GetBytesLength());

	EnHandleResult Result = HR_OK;

	LPTSocketTask Task = HP_Create_SocketTaskObj(Task_ServerSendThreadPool, m_Server, connID, ClienPack.GetBytes(), ClienPack.GetBytesLength(), TBT_COPY, Result);

	if (!m_Pool->Submit(Task))
	{
		HP_Destroy_SocketTaskObj(Task);
	}
	return TRUE;
}

void TeririServer::AnalysisPack(TSocketTask* pTask)
{
	VMProtectBegin(__FUNCTION__);

	PackReader	Pack = PackReader((BYTE*)pTask->buf, pTask->bufLen);

	Pack.SetIndex(2);

	//去掉头部标识
	PackWriter Recv = PackWriter(Pack.GetSize() - Pack.GetIndex());

	AesEncrypt(Pack, Recv, AES_DECRYPT);


	//判断MD5
	Pack = PackReader((BYTE*)Recv.GetBytes(), Recv.GetSize());

	char* cur_md5 = Pack.ReadStr();

	std::string src_md5 = CalcMd5( Pack.GetOffsetBuffer(), Pack.GetBytesAvailable());

	if (lstrcmpA(cur_md5, src_md5.c_str()) != 0)
	{
#if ANTI_DEBUG
		AntiFileError("cur_md5:%s src_md5:%s", cur_md5, src_md5.c_str());
#endif
		//MD5校验失败-通知回调消息-断开连接
		MessageRecvHand(pTask->connID, TERI_DISONNECT_TYPE::TERI_DISCT_MD5);
		//断开连接
		disconnectClient(pTask->connID);
		return;

	}

	int CurOffset = Pack.GetIndex();

	int Index = Pack.ReadShort();

	if (Index > 255)
	{
		//MD5校验失败-通知回调消息-断开连接
		MessageRecvHand(pTask->connID, TERI_DISONNECT_TYPE::TERI_DISCT_FUN);
		//断开连接
		disconnectClient(pTask->connID);

		return;
	}

	//除了版本验证其他功能都需要判断令牌
	if (Index != TERI_IDX_VER)
	{
		//客户端令牌
		std::string	client_token = Pack.ReadStr();

		//查找连接ID
		std::map<CONNID, PTAG_TERI_CLIENT_INFO>::iterator it = GetMapClentInfo()->find(pTask->connID);

		BOOL bResult = TRUE;

		if (it == GetMapClentInfo()->end())
		{
			//没找到.踢出服务端
			bResult = FALSE;;

			//通知回调
			MessageRecvHand(pTask->connID, TERI_DISONNECT_TYPE::TERI_DISCT_CONNID);

		}
		else
		{
			//判断Token

			if (it->second->Token != client_token)
			{
				bResult = FALSE;
#if ANTI_DEBUG
				AntiFileError("[%s]令牌校验错误/ sava_token:%s recv_token:%s",__FUNCTION__, it->second->Token.c_str(), client_token.c_str());

#endif
				MessageRecvHand(pTask->connID, TERI_DISONNECT_TYPE::TERI_DISCT_TOKEN);

			}
		}

		if (bResult == FALSE)
		{
			disconnectClient(pTask->connID);

			return;
		}

	}
	//保存当前的封包偏移
	int nSavaOffset = Pack.GetIndex();

	//设置封包偏移功能索引
	Pack.SetIndex(CurOffset);

	// 通知回调函数
	EnHandleResult Result = OnRecvHand(pTask->connID, Pack.GetOffsetBuffer(), Pack.GetBytesAvailable());

	//恢复
	Pack.SetIndex(nSavaOffset);

	if (Result == HR_OK)
	{
		
		EnHandleResult	EnResult = HR_OK;


		//功能选项
		switch (Index)
		{
		case TERI_IDX_VER:
			EnResult = packIndexVerCheck(Index, Pack, pTask->connID);
			break;
		case TERI_IDX_HEAR:
			EnResult = packIndexHeart(Index, Pack, pTask->connID);
			break;
		case TERI_IDX_CLINFO:
			EnResult = packIndexClienInfo(Index, Pack, pTask->connID);
			break;
		case TERI_IDX_GAME_USER_INFO:
			EnResult = packIndexGameUserInfo(Index, Pack, pTask->connID);
			break;

		default:
			break;
		}



	}


	if (Result == HR_ERROR)
	{
		disconnectClient(pTask->connID);
	}

	VMProtectEnd();
}
