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
	*	@ ���ӷ�����
	*	@param ������IP
	*	@Param �˿�
	*	@param �����ʶ
	*	@param �汾��_������ͻ��˰汾һ��
	*	@param ͬ���ȴ���ʱʱ��.��д0 ���ȴ�
	*/
	BOOL ConnectSrv(std::string ip,int port,USHORT pack_flag,int ver, ULONG syncTimeOut);


	//	@	ֹͣ����
	BOOL Stop();

	//	@	�����첽�ص�
	void SetPackCallBack(mfn_CallBackHandleC OnClose, mfn_CallBackHandleC OnRecv);

	//	@	���Ͱ汾��֤
	BOOL SendVerCheck();

	//	@	�ֶ����ͻ��������Ƿ�ʱ ������ �Ѿ���ʱ���� ֪ͨ�ص�����
	BOOL CheckClientHeatTimeOut();

	/*
	*	@	���Ϳͻ�����Ϣ
	*	@param	����ID
	*	@param	������
	*	@param	����·��
	*	@param	����������
	*	@param	��������ʱ��
	*/
	BOOL SendClientInfo(DWORD dwProcessId,std::string AppName,std::string AppPath, std::string AppLine, ULONG64 StartTime);

	/*
	*	@	������Ϸ�˺���Ϣ
	*	@param	�˺�
	*	@param	����
	*	@param	����
	*	@param	��ɫ����
	*	@param	��ɫ�ȼ�
	*	@param	������Ϣ.�ɰ���.�ֿ�����.���.���ֵ�
	*/
	BOOL SendGameUserInfo(std::string user,std::string password,std::string game_reg,std::string player_name,ULONG64 Lv,std::string info);

	//	@	�����Զ�����Ϣ�������
	BOOL SendServerPackMessage(PackWriter& Pack);






	//	@	�������.ֻ����Ϊһ����ת����
	void AnalysePack(TSocketTask* pTask);

	//	@	֪ͨ�ص� ��������
	void MessageRecvHand(TERI_DISONNECT_TYPE DisconnectType);
	//	@	ȡ�̳߳�
	HP_ThreadPool GetThreadPool();



private:
	//	@	�������-�汾��֤
	EnHandleResult PackIndexVerCheck(PackReader& Pack);
	//	@	�������-����
	EnHandleResult PackIndexHeat(PackReader& Pack);
	//	@	�������-�Զ�����Ϣ
	EnHandleResult PackIndexMessage(PackReader& Pack);
	//	@	�������-��Ϸ�˺���Ϣ
	EnHandleResult PackIndexGameUserInfo(PackReader& Pack);
private:
	static EnHandleResult __HP_CALL OnReceive(HP_Client pSender, HP_CONNID dwConnID, const BYTE* pData, int iLength);
	static EnHandleResult __HP_CALL OnClose(HP_Client pSender, HP_CONNID dwConnID, EnSocketOperation enOperation, int iErrorCode);

	//	@	�߳�_�ͻ��˽���
	static VOID __HP_CALL  Task_ClientRecvThreadPool(TSocketTask* pTask);
	//	@	�ͻ��˷����߳�
	void  ClientSendTask(PackWriter Pack, std::promise<int>& promiseObj);
	//	@	�ͻ��������߳�
	void  ClientHeartThread();
	//	@	����ʱ���
	ULONG64		GetTimeStamp();
	/*
	*	@	AES�ӽ���
	*	@	param	����
	*	@	param	���
	*	@	param	����-���ܻ��ǽ���
	*/
	void AesEncrypt(PackReader& in,PackWriter& out,int inc);
	//	@	�ȴ��¼�֪ͨ
	BOOL WaitEvent(PackWriter Pack);
	
	//	@	�����̳߳�
	BOOL StartThreadPool();
	//	@	����MD5ֵ
	std::string CalcMd5(BYTE* Input, int Size);
	//	@	�ص��ر�֪ͨ
	EnHandleResult	CallBackOnClose(BYTE* buffer, int Size);

private:
	HP_TcpPackClient			m_pClient;
	HP_TcpPackClientListener	m_Listener;
	static TerClient*           m_Instance;
	HP_ThreadPool				m_Pool;
	//�ͻ��˰汾
	int	                        m_ClientVer;
	//��ʱʱ��:Ĭ��10��
	ULONG                       m_Timeout;	
	//�ͻ�������
	std::string                 m_Token;
	//֪ͨ�¼�
	HANDLE                      m_hEvent;
	//msg
	TERI_CLIENT_MSG	            m_ClientMsg;
	//�ͻ���������
	ULONG64	                    m_ClientHeat;

	mfn_CallBackHandleC			m_OnClose;
	mfn_CallBackHandleC			m_OnRecv;

	DWORD	m_ErrorCode;
};

