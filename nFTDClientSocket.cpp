#include "pch.h"
#include "nFTDClientSocket.h"

#include "../../Common/Functions.h"

#include <mstcpip.h>

extern HMODULE g_hRes;
extern RSAKey g_rsakey;


CnFTDClientSocket::CnFTDClientSocket()
{
	m_iServerNum = 0;
	m_bIsN2NConnectionTiming = FALSE;
}

CnFTDClientSocket::~CnFTDClientSocket()
{

}

BOOL CnFTDClientSocket::Connection()
{
	if (m_dwConnection == CONNECTION_CONNECT)
	{
		logWrite(_T("CONNECTION_CONNECT"));

		in_addr Inaddr;
		Inaddr.S_un.S_addr = m_addr;

		if (m_iServerNum != 0)
		{
			//Sleep(2000);
		}

		BOOL bRet = FALSE;
		// 프록시 터널링 초기화
		// 서비스 모드인경우 레지스트리에서 얻어오고
		// 아닌 경우 IE에서 읽어온다
		if (true)//neturoService::RunningAsService() == TRUE)
		{
			logWrite(_T("RunningAsService TRUE"));

			char buffer[256] = "Software\\Optimal\\RCS";
			char buffer2[256] = "\\proxy";
#ifdef LMM_SERVICE
			strcat(buffer, buffer2);
			TunnelingInit(BLASTSOCK_PROXYTUNNELING, NULL, false, false, false, HKEY_LOCAL_MACHINE, "nFTDClient");

#elif ANYSUPPORT
			ZeroMemory(buffer, 256);
#ifdef LINKVNC
			LoadStringA(g_hRes, IDS_REG_HKEY_LOCAL_MACH_LINKVNC, buffer, 256);
#elif LINKEIGHT
			LoadStringA(g_hRes, IDS_REG_HKEY_LOCAL_MACH_LINKEIGHT, buffer, 256);
#else
			LoadStringA(g_hRes, IDS_REG_HKEY_LOCAL_MACH_ANYSUPPORT, buffer, 256);
#endif // LINKVNC
			TunnelingInit(BLASTSOCK_PROXYTUNNELING, NULL, false, false, false, HKEY_LOCAL_MACHINE, buffer);
#else // !ANYSUPPORT
			TunnelingInit(BLASTSOCK_NO_PROXYTUNNELING, NULL, false, false, false, HKEY_LOCAL_MACHINE, buffer);
#endif // ANYSUPPORT
		}
		else
		{
			logWrite(_T("RunningAsService FALSE"));

#ifdef LMM_SERVICE
			TunnelingInit(BLASTSOCK_PROXYTUNNELING, NULL, true, false, true, HKEY_CURRENT_USER, "nFTDClient");

#elif ANYSUPPORT
			TunnelingInit(BLASTSOCK_PROXYTUNNELING, NULL, true, false, true, HKEY_CURRENT_USER, NULL);
#else
			TunnelingInit(BLASTSOCK_NO_PROXYTUNNELING, NULL, true, false, true, HKEY_CURRENT_USER, NULL);
#endif
		}

		logWrite(_T("RunningAsService END"));

		for (int i = 0; i < 10; i++)
		{
			if (!Create())
			{
				continue;
			}

			bRet = Connect(inet_ntoa(Inaddr), m_port);
			if (bRet)
			{
				break;
			}

			Sleep(1000);
		}

		logWrite(_T("Connect"));

		if (!bRet)
		{
			logWriteE(_T("Connect Fail"));
			return FALSE;
		}

		if (m_iServerNum != 0)
		{
			// N2N 일 경우에는 일단 N2N서버와 암호화를 한다
#ifdef _NO_CRYPT
			if (!CryptInit(BLASTSOCK_NO_CRYPT, NULL, &g_rsakey))
				return FALSE;
#else
			if (!CryptInit(BLASTSOCK_CRYPT_RECVAESKEY, NULL, &g_rsakey))
				return FALSE;
#endif

			msg_server_num server_num;

			// N2N과의 커넥션타이밍을 맞추기 위해
			// Neturo Host 가 처음 N2N과 접속할때 하는짓을 한다.
			if (m_bIsN2NConnectionTiming == TRUE)
			{
				server_num.command = 610;
			}
			else
			{
				// nFTD가 N2N과의 커넥션타이밍을 맞출때는 700으로
				server_num.command = AP2P_NFTD_C_SERVERNUM;
			}
			server_num.servernum = m_iServerNum;
			if (!SendExact((LPSTR)&server_num, sizeof(msg_server_num)))
			{
				logWriteE(_T("Send servernum Fail"));
				return FALSE;
			}
		}

		logWrite(_T("N2N"));

#ifdef _NO_CRYPT
		if (CryptInit(BLASTSOCK_NO_CRYPT, NULL, &g_rsakey)) {
#else
		if (CryptInit(BLASTSOCK_CRYPT_RECVAESKEY, NULL, &g_rsakey)) {
#endif
			logWrite(_T("Command Socket CryptInit Success"));
		}
		else {
			logWriteE(_T("Command Socket CryptInit Fail"));
		}
		}
	else
	{
		logWrite(_T("not CONNECTION_CONNECT case..."));

		blastsock sock;
		if (!sock.Create())
		{
			logWriteE(_T("Socket Create Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Create()"));

		int optval = 1;
		SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

		if (!sock.Bind(m_port))
		{
			logWriteE(_T("Socket Bind Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Bind(%d)"), m_port);

		if (!sock.Listen())
		{
			logWriteE(_T("Socket Listen Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Listen()"));

		if (!sock.Accept(*this))
		{
			logWriteE(_T("Socket Accept Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Accept()"));

		sock.CloseSocket();
#ifdef _NO_CRYPT
		CryptInit(BLASTSOCK_NO_CRYPT, NULL, &g_rsakey);
#else
		CryptInit(BLASTSOCK_CRYPT_RECVAESKEY, NULL, &g_rsakey);
#endif
	}

	tcp_keepalive keepAlive = { TRUE, 60000, 1000 };
	DWORD dwTmp;

	// 킵얼라이브 옵션을 켠다. 
	// 컴파일하려면 mstcpip.h 헤더 파일이 필요하다(platform sdk 참조).
	WSAIoctl(this->GetSocket(), SIO_KEEPALIVE_VALS, &keepAlive, sizeof(keepAlive), 0, 0, &dwTmp, NULL, NULL);

	logWrite(_T("End"));

	return TRUE;
}

// @section MODIFYINFO  
//          20170404 - albatross : 파일 매니저를 통하여 다중 파일 전송시 파일 내용 섞이는 이슈 수정 (SendFile, RecvFile시 길이를 보내도록 수정)                 
//                                while 루프를 돌며 실제 파일전송을 하는 도중 파일내용이 변경될때 문제가 생기는지는 확인필
BOOL CnFTDClientSocket::SendFile(LPCTSTR lpFromPathName, LPCTSTR lpToPathName, ULARGE_INTEGER& ulFileSize)
{
	CTime t = CTime::GetCurrentTime();
	CString startTime;
	startTime.Format(_T("%02d:%02d:%02d"), t.GetHour(), t.GetMinute(), t.GetSecond());

	msg ret;
	USHORT usLength;
	ULARGE_INTEGER ulExistFileSize; ulExistFileSize.QuadPart = 0;
	HANDLE hFile;
	ULARGE_INTEGER ulTemp; ulTemp.QuadPart = 0; // 20170404

	// recv file information
	if (!RecvExact((LPSTR)&usLength, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}

	LPTSTR lpPathName = new TCHAR[usLength + 1]; ZeroMemory(lpPathName, (usLength + 1) * sizeof(TCHAR));
	if (!RecvExact((LPSTR)lpPathName, usLength, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
	lpPathName[usLength / 2] = '\0';
	CString fileName;
	fileName.Format(_T("%s"), lpPathName);

	// File Open
	hFile = CreateFile(lpPathName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) // Fail
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());

		ret.type = nFTD_ERROR;
		if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-4 : %d "), GetLastError());
			return FALSE;
		}

		delete[] lpPathName;
		return FALSE;
	}

	// 20170404 : 파일사이즈 전송추가
	//ret.type = nFTD_OK;
	//if(!SendExact((LPSTR)&ret, sz_msg,BLASTSOCK_BUFFER)) return FALSE;

	ret.type = nFTD_FileSize;
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-5 : %d "), GetLastError());
		return FALSE;
	}
	ulFileSize.LowPart = GetFileSize(hFile, &(ulFileSize.HighPart));
	if (!SendExact((LPSTR)&ulFileSize, sizeof(ULARGE_INTEGER), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-6 : %d "), GetLastError());
		return FALSE;
	}

	if (!RecvExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-7 : %d "), GetLastError());
		return FALSE;
	}

	if (ret.type == nFTD_ERROR || ret.type == nFTD_FileIgnore)
	{
		logWriteE(_T("CODE-8 : %d "), GetLastError());

		CloseHandle(hFile);
		delete[] lpPathName;
		return FALSE;
	}
	else if (ret.type == nFTD_FileContinue)
	{
		if (!RecvExact((LPSTR)&ulExistFileSize, sizeof(ULARGE_INTEGER), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-9 : %d "), GetLastError());
			return FALSE;
		}

		SetFilePointer(hFile, ulExistFileSize.LowPart, (LONG*)&ulExistFileSize.HighPart, FILE_BEGIN);
		ulTemp.QuadPart += ulExistFileSize.QuadPart;
	}

	// file send
	delete[] lpPathName;

	DWORD dwBytesRead;
	LPSTR packet = new CHAR[4096];

	DWORD dwStartTicks = GetTickCount();
	ULONGLONG sendedSize = 0;
	int nCompareSpeed = GetPrivateProfileInt(_T("FILE"), _T("SPEED"), 0, get_exe_directory() + _T("\\config.ini"));

	if (g_FT_mode != FT_MODE_AP2P)
		nCompareSpeed = 0;

	logWrite(_T("nCompareSpeed = %d"), nCompareSpeed);

	do
	{
		ReadFile(hFile, packet, 4096, &dwBytesRead, NULL);

		// 20170404 : 파일전송 도중 파일길이 늘어나면 파일 섞일 가능성이 있다.
		//            사전에 약속한길이만큼만 보내준다.
		ULARGE_INTEGER remainSize;
		remainSize.QuadPart = ulFileSize.QuadPart - ulTemp.QuadPart;

		if (remainSize.QuadPart < dwBytesRead)
		{
			dwBytesRead = remainSize.LowPart;
		}

#ifdef MOBILE_FILETRANSFER
		//if(!SendExact(packet, dwBytesRead, BLASTSOCK_BUFFER))
		if (dwBytesRead > 0 && !SendExact(packet, dwBytesRead, BLASTSOCK_BUFFER))
#else
		if (!SendExact(packet, dwBytesRead, BLASTSOCK_NO_BUFFER))
#endif
		{
			logWriteE(_T("CODE-10 : %d "), GetLastError());

			delete[] packet;
			CloseHandle(hFile);
			return FALSE;
		}

		// 20170404 : 정해진 길이를 모두 보냈는지 체크
		ulTemp.QuadPart += dwBytesRead;

#ifdef LMM_SERVICE
		if (nCompareSpeed > 0)
		{
			sendedSize += dwBytesRead;
			DWORD dwEndTicks = GetTickCount();
			DWORD t = dwEndTicks - dwStartTicks;
			if (t == 0)
			{
				t = 1;
			}

			if (t > 1000)
			{
				t = 1000;
			}

			double realSpeed = (double)sendedSize * (double)1000 / (double)t;
			//double realSpeed = sendedSize * 1000;
			if (realSpeed > nCompareSpeed)
			{
				//Sleep((realSpeed * t / nCompareSpeed) - t);
				Sleep(1000 - (1000 * nCompareSpeed / realSpeed));
			}
			if (t >= 1000)
			{
				sendedSize = 0;
				dwStartTicks = dwEndTicks;
			}
		}
#endif

		if (ulTemp.QuadPart >= ulFileSize.QuadPart)
		{
			break;
		}
	} while (dwBytesRead == 4096);

	delete[] packet;
	CloseHandle(hFile);

#ifdef ANYSUPPORT
	INT i = fileName.ReverseFind(_T('\\')) + 1;
	CString action;
	action.LoadString(AfxGetResourceHandle(), NFTD_IDS_SEND);
	CLog::GetLog()->WriteTransferLog(fileName.Mid(i), fileName.Left(i), action, startTime);
#endif

	/*
	if(!RecvExact((LPSTR)&ret, sz_msg,BLASTSOCK_BUFFER))
	{
		logWrite(_T("[CnFTDClientSocket::SendFile][Error] CODE-11 : %d "), GetLastError());
		return FALSE;
	}
	*/

	return TRUE;
}

BOOL CnFTDClientSocket::RecvFile(LPCTSTR lpFromPathName, LPCTSTR lpToPathName, ULARGE_INTEGER& ulFileSize)
{
	CTime t = CTime::GetCurrentTime();
	CString startTime;
	startTime.Format(_T("%02d:%02d:%02d"), t.GetHour(), t.GetMinute(), t.GetSecond());

	msg ret;
	USHORT usLength;
	ULARGE_INTEGER ulSize;
	ULARGE_INTEGER ulExistFileSize;

	if (!RecvExact((LPSTR)&usLength, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	LPTSTR lpPathName = new TCHAR[usLength + 1]; ZeroMemory(lpPathName, (usLength + 1) * sizeof(TCHAR));
	if (!RecvExact((LPSTR)lpPathName, usLength, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
	lpPathName[usLength / 2] = '\0';
	CString fileName;
	fileName.Format(_T("%s"), lpPathName);

	if (!RecvExact((LPSTR)&ulSize, sizeof(ULARGE_INTEGER), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return FALSE;
	}

	HANDLE hFile = CreateFile(lpPathName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());

		ret.type = nFTD_ERROR;
		if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-5 : %d "), GetLastError());
			return FALSE;
		}

		delete[] lpPathName;
		return FALSE;
	}
	else
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			ret.type = nFTD_FileExist;
			if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-6 : %d "), GetLastError());
				return FALSE;
			}
			ulExistFileSize.LowPart = GetFileSize(hFile, &(ulExistFileSize.HighPart));
			if (!SendExact((LPSTR)&ulExistFileSize, sizeof(ULARGE_INTEGER), BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-7 : %d "), GetLastError());
				return FALSE;
			}

			if (!RecvExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-8 : %d "), GetLastError());
				return FALSE;
			}
			if (ret.type == nFTD_FileContinue)
			{
				ulSize.QuadPart -= ulExistFileSize.QuadPart;
				SetFilePointer(hFile, 0, NULL, FILE_END);
			}
			else if (ret.type == nFTD_FileOverWrite)
			{
				CloseHandle(hFile);
				hFile = CreateFile(lpPathName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else if (ret.type == nFTD_FileIgnore)
			{
				CloseHandle(hFile);
				delete[] lpPathName;
				return TRUE;
			}
		}
		else
		{
			ret.type = nFTD_OK;
			if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-9 : %d "), GetLastError());
				return FALSE;
			}
		}
	}

	// transfer
	DWORD dwBytesRead = 4096;
	DWORD dwBytesWrite;
	LPSTR packet = new CHAR[4096];

	do
	{
		if (ulSize.HighPart == 0 && ulSize.LowPart < dwBytesRead)
			dwBytesRead = ulSize.LowPart;
#ifdef MOBILE_FILETRANSFER
		if (ulSize.QuadPart > 0 && !RecvExact(packet, (INT)dwBytesRead, BLASTSOCK_BUFFER))
#else
		if (ulSize.QuadPart > 0 && !RecvExact(packet, (INT)dwBytesRead, BLASTSOCK_NO_BUFFER))
#endif
		{
			logWriteE(_T("CODE-10 : %d "), GetLastError());
			CloseHandle(hFile);
			return FALSE;
		}
		WriteFile(hFile, packet, dwBytesRead, &dwBytesWrite, NULL);
		ulSize.QuadPart -= dwBytesRead;
	} while (dwBytesRead == 4096);

	delete[] lpPathName;
	delete[] packet;
	CloseHandle(hFile);

#ifdef ANYSUPPORT
	INT i = fileName.ReverseFind(_T('\\')) + 1;
	CString action;
	action.LoadString(AfxGetResourceHandle(), NFTD_IDS_RECV);
	CLog::GetLog()->WriteTransferLog(fileName.Mid(i), fileName.Left(i), action, startTime);
#endif
	/*
	ret.type = nFTD_OK;
	if(!SendExact((LPSTR)&ret, sz_msg,BLASTSOCK_BUFFER))
	{
		logWrite(_T("[CnFTDClientSocket::RecvFile][Error] CODE-11 : %d "), GetLastError());
		return FALSE;
	}
	*/
	return TRUE;
}

void CnFTDClientSocket::SetSockAddr(ULONG addr, USHORT port, int iServerNum, BOOL bIsN2NConnectionTiming)
{
	m_addr = addr;
	m_port = port;
	m_iServerNum = iServerNum;
	m_bIsN2NConnectionTiming = bIsN2NConnectionTiming;
}

void CnFTDClientSocket::SetConnection(DWORD dwConnection)
{
	m_dwConnection = dwConnection;
}


BOOL CnFTDClientSocket::CreateDirectory(LPCTSTR lpPathName)
{
	msg ret;
	USHORT length;
	LPTSTR PathName = new TCHAR[MAX_PATH];
	ZeroMemory(PathName, MAX_PATH * sizeof(TCHAR));

	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)PathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	if (m_FileManager.CreateDirectory(PathName))
	{
		ret.type = nFTD_OK;
	}
	else
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			ret.type = nFTD_OK;
		}
		else
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			ret.type = nFTD_ERROR;
		}
	}
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}
	delete[] PathName;
	if (ret.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
		return FALSE;
	}
}

BOOL CnFTDClientSocket::Rename(LPCTSTR lpOldName, LPCTSTR lpNewName)
{
	msg ret;
	USHORT length1, length2;
	LPTSTR OldPathName = new TCHAR[MAX_PATH];
	ZeroMemory(OldPathName, MAX_PATH * sizeof(TCHAR));
	LPTSTR NewPathName = new TCHAR[MAX_PATH];
	ZeroMemory(NewPathName, MAX_PATH * sizeof(TCHAR));

	if (!RecvExact((LPSTR)&length1, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)&length2, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)OldPathName, length1, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)NewPathName, length2, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}

	if (m_FileManager.Rename(OldPathName, NewPathName))
	{
		ret.type = nFTD_OK;
	}
	else
	{
		logWriteE(_T("CODE-5 : %d "), GetLastError());
		ret.type = nFTD_ERROR;
	}
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-6 : %d "), GetLastError());
		return FALSE;
	}
	delete[] OldPathName;
	delete[] NewPathName;

	if (ret.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
		return FALSE;
	}
}

BOOL CnFTDClientSocket::DeleteDirectory(LPCTSTR lpPath)
{
	msg ret;
	USHORT length;
	LPTSTR PathName = new TCHAR[MAX_PATH];
	ZeroMemory(PathName, MAX_PATH * sizeof(TCHAR));

	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)PathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	if (m_FileManager.DeleteDirectory(PathName))
	{
		ret.type = nFTD_OK;
	}
	else
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		ret.type = nFTD_ERROR;
	}
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}
	delete[] PathName;
	if (ret.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
		return FALSE;
	}
}

BOOL CnFTDClientSocket::DeleteFile(LPCTSTR lpPathName)
{
	msg ret;
	USHORT length;
	LPTSTR PathName = new TCHAR[MAX_PATH];
	ZeroMemory(PathName, MAX_PATH * sizeof(TCHAR));

	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)PathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	if (m_FileManager.DeleteFile(PathName))
	{
		ret.type = nFTD_OK;
	}
	else
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		ret.type = nFTD_ERROR;
	}

	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}
	delete[] PathName;

	if (ret.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
		return FALSE;
	}
}

BOOL CnFTDClientSocket::DriveList(PUINT pDriveType, LPSTR lpDriveName)
{
	msgDriveInfo msgFindDriveData;
	LPTSTR DriveName = new TCHAR[MAX_PATH];
	ZeroMemory(DriveName, MAX_PATH * sizeof(TCHAR));

	if (!m_FileManager.DriveList(&msgFindDriveData.driveType, DriveName))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());

		delete[] DriveName;
		return FALSE;
	}

	do {
		msgFindDriveData.type = nFTD_OK;
		msgFindDriveData.length = _tcslen(DriveName) * 2;

		if (!SendExact((LPSTR)&msgFindDriveData, sz_msgDriveInfo, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d "), GetLastError());
			return FALSE;
		}
		if (!SendExact((LPSTR)DriveName, msgFindDriveData.length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			return FALSE;
		}

		ZeroMemory(DriveName, MAX_PATH);
		ZeroMemory(DriveName, MAX_PATH);
	} while (m_FileManager.NextDriveList(&msgFindDriveData.driveType, DriveName));

	msgFindDriveData.type = nFTD_END;
	if (!SendExact((LPSTR)&msgFindDriveData, sz_msgDriveInfo, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}
	delete[] DriveName;
	return TRUE;
}

BOOL CnFTDClientSocket::NextDriveList(PUINT pDriveType, LPSTR lpDriveName)
{
	return FALSE;
}

BOOL CnFTDClientSocket::ChangeDirectory(LPCTSTR lpDirName)
{
	msg ret;
	USHORT length;
	LPTSTR DirName = new TCHAR[MAX_PATH];
	ZeroMemory(DirName, MAX_PATH * sizeof(TCHAR));
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}

	if (!RecvExact((LPSTR)DirName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	if (_tcscmp(DirName, _T("바탕화면")) == 0)
	{
		//TCHAR path[MAX_PATH];
		//neturoService::GetSpectialPath(path, GUID_FOLDER_DESKTOP);
		//_tcscpy(DirName, path);

		_stprintf(DirName, _T("%s"), get_known_folder(CSIDL_DESKTOP));
	}
	else if (_tcscmp(DirName, _T("내문서")) == 0)
	{
		//TCHAR path[MAX_PATH];
		//neturoService::GetSpectialPath(path, GUID_FOLDER_MYDOC);
		//_tcscpy(DirName, path);
		_stprintf(DirName, _T("%s"), get_known_folder(CSIDL_PERSONAL));
	}

	if (m_FileManager.ChangeDirectory(DirName))
	{
		ret.type = nFTD_OK;
	}
	else
	{
		ret.type = nFTD_ERROR;
	}

	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return FALSE;
	}

	delete[] DirName;

	if (ret.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
		return FALSE;
	}
}

BOOL CnFTDClientSocket::TotalSpace(PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
	msgDiskSpace msgTotalNumberOfFreeBytes;
#ifdef MOBILE_FILETRANSFER
	ULARGE_INTEGER tempSize;
	if (m_FileManager.TotalSpace(&(tempSize)))
		msgTotalNumberOfFreeBytes.type = nFTD_OK;
	else
		msgTotalNumberOfFreeBytes.type = nFTD_ERROR;

	msgTotalNumberOfFreeBytes.space = tempSize.QuadPart;
#else	
	if (m_FileManager.TotalSpace(&(msgTotalNumberOfFreeBytes.space)))
		msgTotalNumberOfFreeBytes.type = nFTD_OK;
	else
		msgTotalNumberOfFreeBytes.type = nFTD_ERROR;
#endif

	if (!SendExact((LPSTR)&msgTotalNumberOfFreeBytes, sz_msgDiskSpace, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (msgTotalNumberOfFreeBytes.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
}

BOOL CnFTDClientSocket::RemainSpace(PULARGE_INTEGER lpTotalNumberOfRemainBytes)
{
	msgDiskSpace msgTotalNumberOfRemainBytes;
#ifdef MOBILE_FILETRANSFER
	ULARGE_INTEGER tempSize;
	if (m_FileManager.RemainSpace(&(tempSize)))
		msgTotalNumberOfRemainBytes.type = nFTD_OK;
	else
		msgTotalNumberOfRemainBytes.type = nFTD_ERROR;
	msgTotalNumberOfRemainBytes.space = tempSize.QuadPart;
#else
	if (m_FileManager.RemainSpace(&(msgTotalNumberOfRemainBytes.space)))
		msgTotalNumberOfRemainBytes.type = nFTD_OK;
	else
		msgTotalNumberOfRemainBytes.type = nFTD_ERROR;
#endif

	if (!SendExact((LPCSTR)&msgTotalNumberOfRemainBytes, sz_msgDiskSpace, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (msgTotalNumberOfRemainBytes.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
}

BOOL CnFTDClientSocket::CurrentPath(DWORD nBufferLength, LPTSTR lpCurrentPath)
{
	msgString1 str1;

	str1.length = 1024;
	LPTSTR PathName = new TCHAR[str1.length];
	ZeroMemory(PathName, str1.length * sizeof(TCHAR));

	if (m_FileManager.CurrentPath(str1.length, PathName))
	{
		str1.type = nFTD_OK;
	}
	else
	{
		str1.type = nFTD_ERROR;
	}

	str1.length = _tcslen(PathName) * 2;

	if (!SendExact((LPSTR)&str1, sz_msgString1, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}

	if (str1.type == nFTD_OK)
	{
		if (!SendExact((LPSTR)PathName, str1.length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d "), GetLastError());
			return FALSE;
		}
	}
	delete[] PathName;
	if (str1.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
		return FALSE;
	}
}

BOOL CnFTDClientSocket::GetDesktopPath()
{
	WIN32_FIND_DATA	FindFileData;
	TCHAR path[MAX_PATH];

	ZeroMemory(path, MAX_PATH * sizeof(TCHAR));

	//neturoService::GetSpectialPath(path, GUID_FOLDER_DESKTOP);
	_stprintf(path, _T("%s"), get_known_folder(CSIDL_DESKTOP));

	msgFileInfo msgFindFileData;
	ZeroMemory(&msgFindFileData, sizeof(msgFileInfo));

	msgFindFileData.type = nFTD_OK;
	msgFindFileData.length = _tcslen(path) * 2;

	if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!SendExact((LPSTR)path, msgFindFileData.length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL CnFTDClientSocket::GetDocumentPath()
{
	WIN32_FIND_DATA	FindFileData;
	TCHAR path[MAX_PATH];

	ZeroMemory(path, MAX_PATH * sizeof(TCHAR));

	//neturoService::GetSpectialPath(path, GUID_FOLDER_MYDOC);
	_stprintf(path, _T("%s"), get_known_folder(CSIDL_PERSONAL));

	msgFileInfo msgFindFileData;
	ZeroMemory(&msgFindFileData, sizeof(msgFileInfo));

	msgFindFileData.type = nFTD_OK;
	msgFindFileData.length = _tcslen(path) * 2;

	if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!SendExact((LPSTR)path, msgFindFileData.length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL CnFTDClientSocket::ExecuteFile()
{
	try
	{
		msg ret;
		USHORT length;
		LPTSTR DirName = new TCHAR[MAX_PATH];
		ZeroMemory(DirName, MAX_PATH * sizeof(TCHAR));
		if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-1 : %d "), GetLastError());
			return FALSE;
		}

		if (!RecvExact((LPSTR)DirName, length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d "), GetLastError());
			return FALSE;
		}

		ShellExecute(NULL, _T("open"), DirName, NULL, NULL, SW_SHOWNORMAL);

		ret.type = nFTD_OK;
		if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			return FALSE;
		}

		delete[] DirName;
		return TRUE;
	}
	catch (...)
	{
		return FALSE;
	}
}

BOOL CnFTDClientSocket::FileInfo(WIN32_FIND_DATA* pFileInfo)
{
	USHORT length;
	LPTSTR lpPathName = new TCHAR[MAX_PATH];
	ZeroMemory(lpPathName, MAX_PATH * sizeof(TCHAR));
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)lpPathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	msgFileInfo2 msgFindFileData;
	WIN32_FIND_DATA	FindFileData;
	if (_taccess(lpPathName, 0) != 0)
	{
		msgFindFileData.type = nFTD_END;
		msgFindFileData.dwFileAttributes = 0;
		if (!SendExact((LPSTR)&msgFindFileData, sizeof(msgFileInfo2), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			return FALSE;
		}
		return FALSE;
	}
	FindFirstFile(lpPathName, &FindFileData);

	msgFindFileData.type = nFTD_OK;
	msgFindFileData.dwFileAttributes = FindFileData.dwFileAttributes;
#ifdef MOBILE_FILETRANSFER
	ULARGE_INTEGER tempSize;
	tempSize.HighPart = FindFileData.nFileSizeHigh;
	tempSize.LowPart = FindFileData.nFileSizeLow;
	msgFindFileData.nFileSize = tempSize.QuadPart;
	msgFindFileData.ftLastWriteTime = (FileTime_to_POSIX(FindFileData.ftLastWriteTime));
#else
	msgFindFileData.nFileSizeHigh = FindFileData.nFileSizeHigh;
	msgFindFileData.nFileSizeLow = FindFileData.nFileSizeLow;
	memcpy(&msgFindFileData.ftLastWriteTime, &FindFileData.ftLastWriteTime, sizeof(FILETIME));
	memcpy(&msgFindFileData.ftCreateTime, &FindFileData.ftCreationTime, sizeof(FILETIME));
#endif

	if (!SendExact((LPSTR)&msgFindFileData, sizeof(msgFileInfo2), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}
	/*
	if(!SendExact((LPSTR)FindFileData.cFileName, msgFindFileData.length, BLASTSOCK_BUFFER))
	{
		logWrite(_T("[CnFTDClientSocket::FileInfo][Error] CODE-4 : %d "), GetLastError());
		return FALSE;
	}

	msg ret;
	ret.type = nFTD_END;
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWrite(_T("[CnFTDClientSocket::FileInfo][Error] CODE-5 : %d "), GetLastError());
		return FALSE;
	}
	*/
	return TRUE;
}

BOOL CnFTDClientSocket::FileList3(WIN32_FIND_DATA* pFileInfo)
{
	USHORT length;
	LPTSTR lpPathName = new TCHAR[MAX_PATH];
	ZeroMemory(lpPathName, MAX_PATH * sizeof(TCHAR));
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)lpPathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	msgFileInfo2 msgFindFileData;
	WIN32_FIND_DATA	FindFileData;
	if (!m_FileManager.FileList(&FindFileData, lpPathName)) return FALSE;
	do {
		msgFindFileData.type = nFTD_OK;
		msgFindFileData.dwFileAttributes = FindFileData.dwFileAttributes;
#ifdef MOBILE_FILETRANSFER
		ULARGE_INTEGER tempSize;
		tempSize.HighPart = FindFileData.nFileSizeHigh;
		tempSize.LowPart = FindFileData.nFileSizeLow;
		msgFindFileData.nFileSize = tempSize.QuadPart;
		msgFindFileData.ftLastWriteTime = (FileTime_to_POSIX(FindFileData.ftLastWriteTime));
#else
		msgFindFileData.nFileSizeHigh = FindFileData.nFileSizeHigh;
		msgFindFileData.nFileSizeLow = FindFileData.nFileSizeLow;
		memcpy(&msgFindFileData.ftLastWriteTime, &FindFileData.ftLastWriteTime, sizeof(FILETIME));
		memcpy(&msgFindFileData.ftCreateTime, &FindFileData.ftCreationTime, sizeof(FILETIME));
#endif
		msgFindFileData.length = _tcslen(FindFileData.cFileName) * 2;

		if (!SendExact((LPSTR)&msgFindFileData, sizeof(msgFileInfo2), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			return FALSE;
		}
		if (!SendExact((LPSTR)FindFileData.cFileName, msgFindFileData.length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-4 : %d "), GetLastError());
			return FALSE;
		}
	} while (m_FileManager.NextFileList(&FindFileData));


	msgFindFileData.type = nFTD_END;
	if (!SendExact((LPSTR)&msgFindFileData, sizeof(msgFileInfo2), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-5 : %d "), GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CnFTDClientSocket::FileList(WIN32_FIND_DATA* pFileInfo)
{
	msgFileInfo msgFindFileData;
	WIN32_FIND_DATA	FindFileData;
	if (!m_FileManager.FileList(&FindFileData))
	{
#ifdef MOBILE_FILETRANSFER
#endif
		logWriteE(_T("CODE-1 : %d "), GetLastError());

		msgFindFileData.type = nFTD_END;
		if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d "), GetLastError());
			return FALSE;
		}
		return FALSE;
	}

	do
	{
		msgFindFileData.type = nFTD_OK;
		msgFindFileData.dwFileAttributes = FindFileData.dwFileAttributes;
#ifdef MOBILE_FILETRANSFER
		ULARGE_INTEGER tempSize;
		tempSize.HighPart = FindFileData.nFileSizeHigh;
		tempSize.LowPart = FindFileData.nFileSizeLow;
		msgFindFileData.nFileSize = tempSize.QuadPart;
		msgFindFileData.ftLastWriteTime = (FileTime_to_POSIX(FindFileData.ftLastWriteTime));
#else
		msgFindFileData.nFileSizeHigh = FindFileData.nFileSizeHigh;
		msgFindFileData.nFileSizeLow = FindFileData.nFileSizeLow;
		memcpy(&msgFindFileData.ftLastWriteTime, &FindFileData.ftLastWriteTime, sizeof(FILETIME));
#endif
		msgFindFileData.length = _tcslen(FindFileData.cFileName) * 2;

		if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			return FALSE;
		}

		if (!SendExact((LPSTR)FindFileData.cFileName, msgFindFileData.length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-4 : %d "), GetLastError());
			return FALSE;
		}
	} while (m_FileManager.NextFileList(&FindFileData));

	msgFindFileData.type = nFTD_END;
	if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-5 : %d "), GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CnFTDClientSocket::FileList2(WIN32_FIND_DATA* pFileInfo)
{
	// 시작 경로를 얻는다.
	/*
	USHORT usLength;
	// recv file information
	if(!RecvExact((LPSTR)&usLength, sizeof(USHORT),BLASTSOCK_BUFFER)) return FALSE;
	LPTSTR lpPathName = new TCHAR[usLength/2+1]; ZeroMemory(lpPathName, usLength/2+1);
	if(!RecvExact((LPSTR)lpPathName, usLength,BLASTSOCK_BUFFER)) return FALSE;
	lpPathName[usLength] = '\0';
	*/

	USHORT length;
	LPTSTR lpPathName = new TCHAR[MAX_PATH];
	ZeroMemory(lpPathName, MAX_PATH * sizeof(TCHAR));
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	logWrite(_T("received length = %d"), length);

	if (!RecvExact((LPSTR)lpPathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
	logWrite(_T("receive lpPathName = %s"), lpPathName);

	msgFileInfo msgFindFileData;
	WIN32_FIND_DATA	FindFileData;
	if (!m_FileManager.FileList(&FindFileData, lpPathName)) return FALSE;
	do {
		msgFindFileData.type = nFTD_OK;
		msgFindFileData.dwFileAttributes = FindFileData.dwFileAttributes;
#ifdef MOBILE_FILETRANSFER
		ULARGE_INTEGER tempSize;
		tempSize.HighPart = FindFileData.nFileSizeHigh;
		tempSize.LowPart = FindFileData.nFileSizeLow;
		msgFindFileData.nFileSize = tempSize.QuadPart;
		msgFindFileData.ftLastWriteTime = (FileTime_to_POSIX(FindFileData.ftLastWriteTime));
#else
		msgFindFileData.nFileSizeHigh = FindFileData.nFileSizeHigh;
		msgFindFileData.nFileSizeLow = FindFileData.nFileSizeLow;
		memcpy(&msgFindFileData.ftLastWriteTime, &FindFileData.ftLastWriteTime, sizeof(FILETIME));
#endif
		msgFindFileData.length = _tcslen(FindFileData.cFileName) * 2;

		if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d "), GetLastError());
			return FALSE;
		}
		if (!SendExact((LPSTR)FindFileData.cFileName, msgFindFileData.length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-4 : %d "), GetLastError());
			return FALSE;
		}
	} while (m_FileManager.NextFileList(&FindFileData));


	msgFindFileData.type = nFTD_END;
	if (!SendExact((LPSTR)&msgFindFileData, sz_msgFileInfo, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-5 : %d "), GetLastError());
		return FALSE;
	}
	return TRUE;
}

BOOL CnFTDClientSocket::NextFileList(WIN32_FIND_DATA* pFileInfo)
{
	return FALSE;
}

BOOL CnFTDClientSocket::FileSize(LPTSTR lpPathName, ULARGE_INTEGER* ulSize)
{
	USHORT length;
	ULARGE_INTEGER ulFileSize;
	msgFileSize MsgFileSize;

	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	LPTSTR PathName = new TCHAR[length + 1]; ZeroMemory(PathName, (length + 1) * sizeof(TCHAR));
	if (!RecvExact((LPSTR)PathName, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}
	PathName[length / 2] = '\0';

	if (m_FileManager.FileSize(PathName, &ulFileSize))
	{
		MsgFileSize.type = nFTD_OK;
	}
	else
	{
		MsgFileSize.type = nFTD_ERROR;
	}

#ifdef MOBILE_FILETRANSFER
	MsgFileSize.nFileSize = ulFileSize.QuadPart;
#else
	MsgFileSize.nFileSizeHigh = ulFileSize.HighPart;
	MsgFileSize.nFileSizeLow = ulFileSize.LowPart;
#endif

	if (!SendExact((LPSTR)&MsgFileSize, sz_msgFileSize, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return FALSE;
	}
	delete[] PathName;

	if (MsgFileSize.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());
		return FALSE;
	}
}

bool CnFTDClientSocket::filelist_all()
{
	msg ret;
	USHORT length;
	LPTSTR path = new TCHAR[MAX_PATH];
	ZeroMemory(path, MAX_PATH * sizeof(TCHAR));

	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return false;
	}

	if (!RecvExact((LPSTR)path, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	std::deque<WIN32_FIND_DATA> dq;
	find_all_files(path, &dq, _T("*"), true);

	length = sizeof(WIN32_FIND_DATA);

	for (int i = 0; i < dq.size(); i++)
	{
		TRACE(_T("%3d = %s\n"), i, dq[i].cFileName);

		//파일명 전송
		if (!SendExact((LPSTR)&dq[i], length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d"), GetLastError());
			return false;
		}
	}

	WIN32_FIND_DATA temp;
	ZeroMemory(&temp, sizeof(temp));

	//끝 신호 전송
	if (!SendExact((LPSTR)&temp, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d"), GetLastError());
		return false;
	}

	return true;
}