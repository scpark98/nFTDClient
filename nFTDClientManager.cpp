#include "pch.h"
#include "nFTDClientManager.h"

#include "../../Common/Functions.h"

CnFTDClientManager::CnFTDClientManager()
{
	m_lpNMSID = NULL;
}

CnFTDClientManager::~CnFTDClientManager()
{
	delete[] m_lpNMSID;
}

BOOL CnFTDClientManager::SetConnection(CString lpCmdLine)
{
	LPSTR lpCmdOpt;
	DWORD dwConnectionMode = 0;
	ULONG ulAddr = 0;
	USHORT ushPort = 0;
	INT iServernum = 0;
	BOOL bIsStandAlone;

	if (__argc < 2)
	{
		logWriteE(_T("Invalid command"));
		return FALSE;
	}

	// address
	//lpCmdOpt = strtok(lpCmdLine, " ");
	if (_tcscmp(__targv[1], _T("-l")) == 0)
	{
		dwConnectionMode = CONNECTION_LISTEN;
		ushPort = _ttoi(__targv[2]);// (USHORT)atoi(strtok(NULL, " "));
		logWrite(_T("dwConnectionMode = CONNECTION_LISTEN. port = %d"), ushPort);
	}
	else if (_tcscmp(__targv[1], _T("-c")) == 0) // P2P connect
	{
		dwConnectionMode = CONNECTION_CONNECT;
		ulAddr = inet_addr(unicodeToMultibyte(__targv[2]).c_str());
		ushPort = _ttoi(__targv[3]);// (USHORT)atoi(strtok(NULL, " "));
		logWrite(_T("dwConnectionMode = CONNECTION_CONNECT. port = %d"), ushPort);
	}
	else if (_tcscmp(__targv[1], _T("-p")) == 0) // AP2P (pat to pat) . NMS 에 접속
	{
		dwConnectionMode = CONNECTION_CONNECT;
		ulAddr = inet_addr(unicodeToMultibyte(__targv[2]).c_str());
		ushPort = _ttoi(__targv[3]);// (USHORT)atoi(strtok(NULL, " "));
		iServernum = _ttoi(__targv[4]);// atoi(strtok(NULL, " "));
		logWrite(_T("dwConnectionMode = CONNECTION_CONNECT. port = %d"), ushPort);
	}
	else
	{
		return FALSE;
	}

	// standalone 인지 여부
	/*
	lpCmdOpt = strtok(NULL, " ");
	if (lpCmdOpt != NULL && !strcmp(lpCmdOpt, "-standalone"))
	{
		//neturoService::SetServiceMode(TRUE);
		bIsStandAlone = TRUE;
		// User ID - for session log
		lpCmdOpt = strtok(NULL, " ");
		if (lpCmdOpt != NULL)
		{
			delete[] m_lpNMSID;
			m_lpNMSID = new char[strlen(lpCmdOpt) + 1];
			ZeroMemory(m_lpNMSID, strlen(lpCmdOpt) + 1);
			strcpy(m_lpNMSID, lpCmdOpt);
		}
	}
	else
	*/
	{
		//neturoService::SetServiceMode(FALSE);
		bIsStandAlone = FALSE;
	}

	m_socket.SetConnection(dwConnectionMode);
	m_socket.SetSockAddr(ulAddr, ushPort, iServernum, bIsStandAlone);
	m_DataSocket.SetConnection(dwConnectionMode);
	m_DataSocket.SetSockAddr(ulAddr, ushPort, iServernum, FALSE);

	return TRUE;
}

BOOL CnFTDClientManager::Connection()
{
	return m_socket.Connection();
}

void CnFTDClientManager::run()
{
	logWrite(_T(""));

	msg ret;
	DWORD dw;
	CHAR szPeerName[16];

	/*
	Log* session_log;
	// m_lpNMSID 가 존재한다면 logging 초기화 & 접속시작
	if(m_lpNMSID != NULL)
	{
		session_log = new Log(0, 1, _T("SessionHistory.log"), true);
		session_log->SetMode(2);
		session_log->SetLevel(2);
		ZeroMemory(szPeerName, 16);
		strcpy(szPeerName, m_socket.GetPeerName());

		// For Session Log / Session start
		session_log->Print(1, _T("(id:%s) client connected : %s\r\n"),
				 m_lpNMSID, szPeerName);
	}
	*/

	// 현재 폴더의 경로를 디폴트로 c:\\ 로 한다.
	SetCurrentDirectory(_T("c:\\"));
	TCHAR temp[1024];

	while (1)
	{
		logWrite(_T("Ready"));
		if (!m_socket.RecvExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("Fail Socket Receive"));
			break;
		}

		TRACE(_T("ret.type = %d\n"), ret.type);

		switch (ret.type)
		{
		case nFTD_CreateDirectory:
			m_socket.CreateDirectory(NULL);
			logWrite(_T("nFTD_CreateDirectory"));
			break;
		case nFTD_Rename:
			m_socket.Rename(NULL, NULL);
			logWrite(_T("nFTD_Rename"));
			break;
		case nFTD_DeleteDirectory:
			m_socket.DeleteDirectory(NULL);
			logWrite(_T("nFTD_DeleteDirectory"));
			break;
		case nFTD_DeleteFile:
			m_socket.DeleteFile(NULL);
			logWrite(_T("nFTD_DeleteFile"));
			break;
		case nFTD_ChangeDirectory:
			m_socket.ChangeDirectory(NULL);
			logWrite(_T("nFTD_ChangeDirectory"));
			break;
		case nFTD_TotalSpace:
			m_socket.TotalSpace(NULL);
			logWrite(_T("nFTD_TotalSpace"));
			break;
		case nFTD_RemainSpace:
			m_socket.RemainSpace(NULL);
			logWrite(_T("nFTD_RemainSpace"));
			break;
		case nFTD_CurrentPath:
			m_socket.CurrentPath(0, NULL);
			logWrite(_T("nFTD_CurrentPath"));
			break;
		case nFTD_FileSize:
			m_socket.FileSize(NULL, NULL);
			logWrite(_T("nFTD_FileSize"));
			break;
		case nFTD_FileList:
			m_socket.FileList(NULL);
			logWrite(_T("nFTD_FileList"));
			break;
		case nFTD_FileList2:
			m_socket.FileList2(NULL);
			logWrite(_T("nFTD_FileList2"));
			break;
		case nFTD_DriveList:
			m_socket.DriveList(NULL, NULL);
			logWrite(_T("nFTD_DriveList"));
			break;
		case nFTD_DesktopPath:
			//m_socket.GetDesktopPath();
			logWrite(_T("nFTD_DesktopPath"));
			break;
		case nFTD_DocumentPath:
			//m_socket.GetDocumentPath();
			logWrite(_T("nFTD_DocumentPath"));
			break;
		case nFTD_ExecuteFile:
			//m_socket.ExecuteFile();
			logWrite(_T("nFTD_ExecuteFile"));
			break;
		case nFTD_FileInfo:
			//m_socket.FileInfo(NULL);
			logWrite(_T("nFTD_FileInfo"));
			break;
		case nFTD_FileList3:
			//m_socket.FileList3(NULL);
			logWrite(_T("nFTD_FileList3"));
			break;
		case nFTD_OpenDataConnection:
			if (m_DataSocket.Connection())
			{
				//m_hThread = CreateThread(NULL, 0, ThreadProcedure, (LPVOID)this, 0, &dw);
			}
		case nFTD_FileList_All:
			logWrite(_T("nFTD_FileList_All"));
			m_socket.filelist_all();
		}
	}

	// m_lpNMSID 가 존재한다면 접속종료 로그
	if (m_lpNMSID != NULL)
	{
		logWrite(_T("(id:%s) client disconnected : %s\r\n"), m_lpNMSID, szPeerName);
		/*
		session_log->Print(1, _T("(id:%s) client disconnected : %s\r\n"),
				  m_lpNMSID, szPeerName);
		delete session_log;
		*/
	}

	logWrite(_T("End"));
	TerminateThread(m_hThread, 0);
}
