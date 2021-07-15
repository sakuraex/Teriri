#pragma once
#include "TeririBase.h"
#include <TeririHelper.h>






class TeririServer: public CTcpServerListener
{
public:
	TeririServer();
	~TeririServer();

	static TeririServer* GetInstance();

	/*
	*	@ 启动服务
	*	@Param 端口
	*	@param 封包标识
	*	@param 版本号_必须与客户端版本一致
	*/
	BOOL StartSvr(int nPort,USHORT PackFlag,int Ver);

	//	@	停止服务
	BOOL StopSvr();

	//	@	设置回调
	void SetPackCallBack(mfn_CallBackHandle OnAccept, mfn_CallBackHandle OnClose, mfn_CallBackHandle OnRecv);

	//	@	发送自定义消息到客户端
	BOOL SendClientPackMessage(CONNID connID,PackWriter& Pack);



	//	@	解析封包-
	void AnalysisPack(TSocketTask* pTask);


	//	@	功能索引-版本检查
	EnHandleResult packIndexVerCheck(int Index, PackReader& Pack, CONNID connID);
	//	@	功能索引-心跳维持
	EnHandleResult packIndexHeart(int Index, PackReader& Pack, CONNID connID);
	//	@	功能索引-客户端信息
	EnHandleResult packIndexClienInfo(int Index, PackReader& Pack, CONNID connID);
	//	@	功能索引-游戏账号信息
	EnHandleResult packIndexGameUserInfo(int Index, PackReader& Pack, CONNID connID);


	//	@	接受消息回调
	EnHandleResult	OnRecvHand(CONNID connID, BYTE* buffer, int Size);
	//	@	发送包到客户端
	bool ClientSendPack(CONNID dwConnID, PackWriter Pack);
	//	@	踢出客户
	void disconnectClient(CONNID dwConnID);
	//	@	通知断开连接信息类型
	void MessageRecvHand(CONNID connID, TERI_DISONNECT_TYPE DisconnectType);
	//	@	计算MD5值
	std::string  CalcMd5( BYTE* Input, int Size);

	std::map<CONNID, PTAG_TERI_CLIENT_INFO>* GetMapClentInfo();
private:
	//	@	生成一段Token (时间戳+ 连接ID)
	std::string CrateToken(CONNID connID);
	//	@	返回当前时间戳
	ULONG64		GetTimeStamp();
	/*
	*	@	AES加解密
	*	@	param	输入
	*	@	param	输出
	*	@	param	类型-加密还是解密
	*/
	void AesEncrypt(PackReader& in, PackWriter& out, int inc);

private:
	static VOID __HP_CALL  Task_ServerRecvThreadPool(TSocketTask* pTask);
	static VOID __HP_CALL  Task_ServerSendThreadPool(TSocketTask* pTask);
	virtual EnHandleResult OnAccept(ITcpServer* pSender, CONNID dwConnID, SOCKET soClient);
	virtual EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	//检测心跳包线程
	void ThreadCheckHeatPack();

private:
	CTcpPackServerPtr			m_Server;
	IHPThreadPool*              m_Pool;
	static TeririServer*        m_Instance;
	ULONG						m_HeartTimeout;	//心跳超时时间:默认30秒	每10秒发一次
	//Accept 回调
	mfn_CallBackHandle			m_OnAccept;
	mfn_CallBackHandle			m_OnClose;
	mfn_CallBackHandle			m_OnRecv;

	//服务端版本
	int	m_ServerVer;

	std::map<CONNID, PTAG_TERI_CLIENT_INFO>	m_MapToken;

};

