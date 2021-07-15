#pragma once
#include "TerClientBase.h"
#include <TeririHelper.h>


class TerClient
{
public:
	TerClient();
	~TerClient();

	static TerClient* GetInstance();
	/*
	*	@ 连接服务器
	*	@param 服务器IP
	*	@Param 端口
	*	@param 封包标识
	*	@param 版本号_必须与客户端版本一致
	*	@param 同步等待超时时间.填写0 不等待
	*/
	BOOL ConnectSrv(std::string ip,int port,USHORT pack_flag,int ver, ULONG syncTimeOut);


	//	@	停止连接
	BOOL Stop();

	//	@	设置异步回调
	void SetPackCallBack(mfn_CallBackHandleC OnClose, mfn_CallBackHandleC OnRecv);

	//	@	发送版本验证
	BOOL SendVerCheck();

	//	@	手动检查客户端心跳是否超时 返回真 已经超时并且 通知回调函数
	BOOL CheckClientHeatTimeOut();

	/*
	*	@	发送客户端信息
	*	@param	进程ID
	*	@param	进程名
	*	@param	进程路径
	*	@param	进程命令行
	*	@param	进程启动时间
	*/
	BOOL SendClientInfo(DWORD dwProcessId,std::string AppName,std::string AppPath, std::string AppLine, ULONG64 StartTime);

	/*
	*	@	发送游戏账号信息
	*	@param	账号
	*	@param	密码
	*	@param	大区
	*	@param	角色名称
	*	@param	角色等级
	*	@param	其他信息.可包含.仓库资料.金币.积分等
	*/
	BOOL SendGameUserInfo(std::string user,std::string password,std::string game_reg,std::string player_name,ULONG64 Lv,std::string info);

	//	@	发送自定义消息到服务端
	BOOL SendServerPackMessage(PackWriter& Pack);






	//	@	封包分析.只是作为一个中转处理
	void AnalysePack(TSocketTask* pTask);

	//	@	通知回调 断线类型
	void MessageRecvHand(TERI_DISONNECT_TYPE DisconnectType);
	//	@	取线程池
	HP_ThreadPool GetThreadPool();



private:
	//	@	封包索引-版本验证
	EnHandleResult PackIndexVerCheck(PackReader& Pack);
	//	@	封包索引-心跳
	EnHandleResult PackIndexHeat(PackReader& Pack);
	//	@	封包索引-自定义消息
	EnHandleResult PackIndexMessage(PackReader& Pack);
	//	@	封包索引-游戏账号信息
	EnHandleResult PackIndexGameUserInfo(PackReader& Pack);
private:
	static EnHandleResult __HP_CALL OnReceive(HP_Client pSender, HP_CONNID dwConnID, const BYTE* pData, int iLength);
	static EnHandleResult __HP_CALL OnClose(HP_Client pSender, HP_CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);

	//	@	线程_客户端接收
	static VOID __HP_CALL  Task_ClientRecvThreadPool(TSocketTask* pTask);
	//	@	客户端发送线程
	void  ClientSendTask(PackWriter Pack, std::promise<int>& promiseObj);
	//	@	客户端心跳线程
	void  ClientHeartThread();
	//	@	返回时间戳
	ULONG64		GetTimeStamp();
	/*
	*	@	AES加解密
	*	@	param	输入
	*	@	param	输出
	*	@	param	类型-加密还是解密
	*/
	void AesEncrypt(PackReader& in,PackWriter& out,int inc);
	//	@	等待事件通知
	BOOL WaitEvent(PackWriter Pack);
	
	//	@	启动线程池
	BOOL StartThreadPool();
	//	@	计算MD5值
	std::string CalcMd5(BYTE* Input, int Size);
	//	@	回调关闭通知
	EnHandleResult	CallBackOnClose(BYTE* buffer, int Size);

private:
	HP_TcpPackClient			m_pClient;
	HP_TcpPackClientListener	m_Listener;
	static TerClient*           m_Instance;
	HP_ThreadPool				m_Pool;
	//客户端版本
	int	                        m_ClientVer;
	//超时时间:默认10秒
	ULONG                       m_Timeout;	
	//客户端令牌
	std::string                 m_Token;
	//通知事件
	HANDLE                      m_hEvent;
	//msg
	TERI_CLIENT_MSG	            m_ClientMsg;
	//客户端心跳戳
	ULONG64	                    m_ClientHeat;

	mfn_CallBackHandleC			m_OnClose;
	mfn_CallBackHandleC			m_OnRecv;

	DWORD	m_ErrorCode;
};

