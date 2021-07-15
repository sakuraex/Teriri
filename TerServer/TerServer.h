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
	*	@ ��������
	*	@Param �˿�
	*	@param �����ʶ
	*	@param �汾��_������ͻ��˰汾һ��
	*/
	BOOL StartSvr(int nPort,USHORT PackFlag,int Ver);

	//	@	ֹͣ����
	BOOL StopSvr();

	//	@	���ûص�
	void SetPackCallBack(mfn_CallBackHandle OnAccept, mfn_CallBackHandle OnClose, mfn_CallBackHandle OnRecv);

	//	@	�����Զ�����Ϣ���ͻ���
	BOOL SendClientPackMessage(CONNID connID,PackWriter& Pack);



	//	@	�������-
	void AnalysisPack(TSocketTask* pTask);


	//	@	��������-�汾���
	EnHandleResult packIndexVerCheck(int Index, PackReader& Pack, CONNID connID);
	//	@	��������-����ά��
	EnHandleResult packIndexHeart(int Index, PackReader& Pack, CONNID connID);
	//	@	��������-�ͻ�����Ϣ
	EnHandleResult packIndexClienInfo(int Index, PackReader& Pack, CONNID connID);
	//	@	��������-��Ϸ�˺���Ϣ
	EnHandleResult packIndexGameUserInfo(int Index, PackReader& Pack, CONNID connID);


	//	@	������Ϣ�ص�
	EnHandleResult	OnRecvHand(CONNID connID, BYTE* buffer, int Size);
	//	@	���Ͱ����ͻ���
	bool ClientSendPack(CONNID dwConnID, PackWriter Pack);
	//	@	�߳��ͻ�
	void disconnectClient(CONNID dwConnID);
	//	@	֪ͨ�Ͽ�������Ϣ����
	void MessageRecvHand(CONNID connID, TERI_DISONNECT_TYPE DisconnectType);
	//	@	����MD5ֵ
	std::string  CalcMd5( BYTE* Input, int Size);

	std::map<CONNID, PTAG_TERI_CLIENT_INFO>* GetMapClentInfo();
private:
	//	@	����һ��Token (ʱ���+ ����ID)
	std::string CrateToken(CONNID connID);
	//	@	���ص�ǰʱ���
	ULONG64		GetTimeStamp();
	/*
	*	@	AES�ӽ���
	*	@	param	����
	*	@	param	���
	*	@	param	����-���ܻ��ǽ���
	*/
	void AesEncrypt(PackReader& in, PackWriter& out, int inc);

private:
	static VOID __HP_CALL  Task_ServerRecvThreadPool(TSocketTask* pTask);
	static VOID __HP_CALL  Task_ServerSendThreadPool(TSocketTask* pTask);
	virtual EnHandleResult OnAccept(ITcpServer* pSender, CONNID dwConnID, SOCKET soClient);
	virtual EnHandleResult OnReceive(ITcpServer* pSender, CONNID dwConnID, const BYTE* pData, int iLength);
	virtual EnHandleResult OnClose(ITcpServer* pSender, CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);
	//����������߳�
	void ThreadCheckHeatPack();

private:
	CTcpPackServerPtr			m_Server;
	IHPThreadPool*              m_Pool;
	static TeririServer*        m_Instance;
	ULONG						m_HeartTimeout;	//������ʱʱ��:Ĭ��30��	ÿ10�뷢һ��
	//Accept �ص�
	mfn_CallBackHandle			m_OnAccept;
	mfn_CallBackHandle			m_OnClose;
	mfn_CallBackHandle			m_OnRecv;

	//����˰汾
	int	m_ServerVer;

	std::map<CONNID, PTAG_TERI_CLIENT_INFO>	m_MapToken;

};

