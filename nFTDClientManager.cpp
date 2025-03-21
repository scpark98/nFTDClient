#include "pch.h"

#include "nFTDClientManager.h"
#include "../../Common/Functions.h"

#include <thread>

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
	if (_tcscmp(__targv[1], _T("-l")) == 0)		// P2P server
	{
		g_FT_mode = FT_MODE_P2P_S;
		dwConnectionMode = CONNECTION_LISTEN;
		ushPort = _ttoi(__targv[2]);// (USHORT)atoi(strtok(NULL, " "));
		logWrite(_T("dwConnectionMode = CONNECTION_LISTEN. port = %d"), ushPort);
	}
	else if (_tcscmp(__targv[1], _T("-c")) == 0) // P2P connect
	{
		g_FT_mode = FT_MODE_P2P_C;
		dwConnectionMode = CONNECTION_CONNECT;
		ulAddr = inet_addr(unicodeToMultibyte(__targv[2]).c_str());
		ushPort = _ttoi(__targv[3]);// (USHORT)atoi(strtok(NULL, " "));
		logWrite(_T("dwConnectionMode = CONNECTION_CONNECT. port = %d"), ushPort);
	}
	else if (_tcscmp(__targv[1], _T("-p")) == 0) // AP2P (pat to pat) . NMS 에 접속
	{
		g_FT_mode = FT_MODE_AP2P;
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
	logWrite(_T(" "));

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
	TCHAR temp[1024] = { 0, };

	while (1)
	{
		logWrite(_T("Ready"));
		if (!m_socket.RecvExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("Fail Socket Receive"));
			break;
		}

		logWrite(_T("ret.type = %d\n"), ret.type);

		switch (ret.type)
		{
		case nFTD_CreateDirectory:
			logWrite(_T("nFTD_CreateDirectory"));
			m_socket.create_directory(NULL);
			break;
		case nFTD_file_command :
			logWrite(_T("nFTD_file_command"));
			m_socket.file_command();
			break;
		case nFTD_new_folder_index:
			logWrite(_T("nFTD_new_folder_index"));
			m_socket.new_folder_index();
			break;
		case nFTD_Rename:
			logWrite(_T("nFTD_Rename"));
			m_socket.Rename(NULL, NULL);
			break;
		case nFTD_DeleteDirectory:
			logWrite(_T("nFTD_DeleteDirectory"));
			m_socket.delete_directory(NULL);
			break;
		case nFTD_DeleteFile:
			logWrite(_T("nFTD_DeleteFile"));
			m_socket.DeleteFile(NULL);
			break;
		case nFTD_ChangeDirectory:
			logWrite(_T("nFTD_ChangeDirectory"));
			m_socket.change_directory(NULL);
			break;
		case nFTD_TotalSpace:
			logWrite(_T("nFTD_TotalSpace"));
			m_socket.TotalSpace(NULL);
			break;
		case nFTD_RemainSpace:
			logWrite(_T("nFTD_RemainSpace"));
			m_socket.RemainSpace(NULL);
			break;
		case nFTD_CurrentPath:
			logWrite(_T("nFTD_CurrentPath"));
			m_socket.CurrentPath(0, NULL);
			break;
		case nFTD_FileSize:
			logWrite(_T("nFTD_FileSize"));
			m_socket.FileSize(NULL, NULL);
			break;
		case nFTD_FileList:
			logWrite(_T("nFTD_FileList"));
			m_socket.FileList(NULL);
			break;
		case nFTD_FileList2:
			logWrite(_T("nFTD_FileList2"));
			m_socket.FileList2(NULL);
			break;
		case nFTD_DriveList:
			logWrite(_T("nFTD_DriveList"));
			m_socket.DriveList(NULL, NULL);
			break;
		case nFTD_get_system_label:
			logWrite(_T("nFTD_get_system_label"));
			m_socket.get_system_label();
			break;
		case nFTD_get_system_path:
			logWrite(_T("nFTD_get_system_path"));
			m_socket.get_system_path();
			break;
		case nFTD_get_drive_list:
			logWrite(_T("nFTD_get_drive_list"));
			m_socket.get_drive_list();
			break;
			//case nFTD_DesktopPath:
		//	m_socket.GetDesktopPath();
		//	logWrite(_T("nFTD_DesktopPath"));
		//	break;
		//case nFTD_DocumentPath:
		//	m_socket.GetDocumentPath();
		//	logWrite(_T("nFTD_DocumentPath"));
		//	break;
		case nFTD_ExecuteFile:
			logWrite(_T("nFTD_ExecuteFile"));
			m_socket.ExecuteFile();
			break;
		case nFTD_FileInfo:
			logWrite(_T("nFTD_FileInfo"));
			//m_socket.FileInfo(NULL);
			break;
		case nFTD_FileList3:
			logWrite(_T("nFTD_FileList3"));
			//m_socket.FileList3(NULL);
			break;
		case nFTD_OpenDataConnection:
			logWrite(_T("nFTD_OpenDataConnection"));
			if (m_DataSocket.Connection())
			{
				//m_hThread = CreateThread(NULL, 0, ThreadProcedure, (LPVOID)this, 0, &dw);
				std::thread th(&CnFTDClientManager::thread_data_socket, this);
				th.detach();
			}
			break;
		case nFTD_filelist_all:
			logWrite(_T("nFTD_filelist_all"));
			m_socket.filelist_all();
			break;
		case nFTD_folderlist_all:
			logWrite(_T("nFTD_folderlist_all"));
			m_socket.folderlist_all();
			break;
		case nFTD_get_subfolder_count:
			logWrite(_T("nFTD_get_subfolder_count"));
			m_socket.get_subfolder_count();
			break;
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
	//TerminateThread(m_hThread, 0);
}

void CnFTDClientManager::thread_data_socket()
{
	msg ret;
	ULARGE_INTEGER ulTemp;

	while (true)
	{
		if (!m_DataSocket.RecvExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
			break;

		switch (ret.type)
		{
		case nFTD_CreateDirectory:		/*OutputDebugString(_T("Data Socket -- nFTD_CreateDirectory"));*/
			if (!m_DataSocket.create_directory(NULL))
			{
				logWriteE(_T("create_directory ERROR"));
			}
			break;
		case nFTD_ChangeDirectory:		/*OutputDebugString(_T("Data Socket -- nFTD_ChangeDirectory"));*/
			if (!m_DataSocket.change_directory(NULL))
			{
				logWriteE(_T("change_directory ERROR"));
			}
			break;
		case nFTD_FileTransfer:			/*OutputDebugString(_T("Data Socket -- nFTD_FileTransfer"));*/
			if (!m_DataSocket.RecvFile(NULL, NULL, ulTemp))
			{
				logWriteE(_T("RecvFile ERROR"));
			}
			break;
		case nFTD_FileTransferReq:		/*OutputDebugString(_T("Data Socket -- nFTD_FileTransferReq"));*/
			if (!m_DataSocket.SendFile(NULL, NULL, ulTemp))
			{
				logWriteE(_T("SendFile ERROR"));
			}
			break;
		case nFTD_FileList:				/*OutputDebugString(_T("Data Socket -- nFTD_FileList"));*/
			if (!m_DataSocket.FileList(NULL))
			{
				logWriteE(_T("FileList ERROR"));
			}
			break;
		}
	}
}