#pragma once

#include "nFTDClientSocket.h"

class CnFTDClientManager
{
public:
	CnFTDClientManager();
	virtual ~CnFTDClientManager();

	void run();
	BOOL SetConnection(CString lpCmdLine);
	BOOL Connection();
	static DWORD WINAPI ThreadProcedure(LPVOID lpVoid);

private:
	CnFTDClientSocket m_socket;
	CnFTDClientSocket m_DataSocket;
	HANDLE m_hThread;
	LPSTR m_lpNMSID;
};

