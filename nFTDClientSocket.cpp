#include "pch.h"
#include "nFTDClient.h"
#include "nFTDClientDlg.h"
#include "nFTDClientSocket.h"

#include "../../Common/Functions.h"

#include <mstcpip.h>
#include <experimental/filesystem>

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
		// ���Ͻ� �ͳθ� �ʱ�ȭ
		// ���� ����ΰ�� ������Ʈ������ ������
		// �ƴ� ��� IE���� �о�´�
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
			// N2N �� ��쿡�� �ϴ� N2N������ ��ȣȭ�� �Ѵ�
#ifdef _NO_CRYPT
			if (!CryptInit(BLASTSOCK_NO_CRYPT, NULL, &g_rsakey))
				return FALSE;
#else
			if (!CryptInit(BLASTSOCK_CRYPT_RECVAESKEY, NULL, &g_rsakey))
				return FALSE;
#endif

			msg_server_num server_num;

			// N2N���� Ŀ�ؼ�Ÿ�̹��� ���߱� ����
			// Neturo Host �� ó�� N2N�� �����Ҷ� �ϴ����� �Ѵ�.
			if (m_bIsN2NConnectionTiming == TRUE)
			{
				server_num.command = 610;
			}
			else
			{
				// nFTD�� N2N���� Ŀ�ؼ�Ÿ�̹��� ���⶧�� 700����
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
		logWrite(_T("Listening..."));

		blastsock sock;
		if (!sock.Create())
		{
			logWriteE(_T("Socket Create Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Create() success."));

		int optval = 1;
		sock.SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

		if (!sock.Bind(m_port))
		{
			logWriteE(_T("Socket Bind Fail. m_port = %d, error = %d."), m_port, GetLastError());
			return FALSE;
		}
		logWrite(_T("sock.Bind(%d) success."), m_port);

		if (!sock.Listen())
		{
			logWriteE(_T("Socket Listen Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Listen() success."));

		if (!sock.Accept(*this))
		{
			logWriteE(_T("Socket Accept Fail"));
			return FALSE;
		}
		logWrite(_T("sock.Accept() success."));

		sock.CloseSocket();
#ifdef _NO_CRYPT
		CryptInit(BLASTSOCK_NO_CRYPT, NULL, &g_rsakey);
#else
		CryptInit(BLASTSOCK_CRYPT_RECVAESKEY, NULL, &g_rsakey);
#endif
	}

	tcp_keepalive keepAlive = { TRUE, 60000, 1000 };
	DWORD dwTmp;

	// ŵ����̺� �ɼ��� �Ҵ�. 
	// �������Ϸ��� mstcpip.h ��� ������ �ʿ��ϴ�(platform sdk ����).
	WSAIoctl(this->GetSocket(), SIO_KEEPALIVE_VALS, &keepAlive, sizeof(keepAlive), 0, 0, &dwTmp, NULL, NULL);

	logWrite(_T("End"));

	return TRUE;
}

// @section MODIFYINFO  
//          20170404 - albatross : ���� �Ŵ����� ���Ͽ� ���� ���� ���۽� ���� ���� ���̴� �̽� ���� (SendFile, RecvFile�� ���̸� �������� ����)                 
//                                while ������ ���� ���� ���������� �ϴ� ���� ���ϳ����� ����ɶ� ������ ��������� Ȯ����
BOOL CnFTDClientSocket::SendFile(LPCTSTR lpFromPathName, LPCTSTR lpToPathName, ULARGE_INTEGER& ulFileSize)
{
	CTime t = CTime::GetCurrentTime();
	CString startTime;
	startTime.Format(_T("%02d:%02d:%02d"), t.GetHour(), t.GetMinute(), t.GetSecond());

	msg ret;
	USHORT usLength;
	HANDLE hFile;
	ULARGE_INTEGER ulTemp; ulTemp.QuadPart = 0; // 20170404
	ULARGE_INTEGER ulExistFileSize;
	WIN32_FIND_DATA send_file;
	WIN32_FIND_DATA exist_file;

	//fullpath length ����
	//if (!RecvExact((LPSTR)&usLength, sizeof(USHORT), BLASTSOCK_BUFFER))
	//{
	//	logWriteE(_T("CODE-1 : %d "), GetLastError());
	//	return FALSE;
	//}

	////fullpath ����
	//LPTSTR lpPathName = new TCHAR[usLength + 1];
	//ZeroMemory(lpPathName, (usLength + 1) * sizeof(TCHAR));
	//if (!RecvExact((LPSTR)lpPathName, usLength, BLASTSOCK_BUFFER))
	//{
	//	logWriteE(_T("CODE-2 : %d "), GetLastError());
	//	return FALSE;
	//}
	//lpPathName[usLength / 2] = '\0';
	//CString fileName;
	//fileName.Format(_T("%s"), lpPathName);

	//WIN32_FIND_DATA from  ����
	if (!RecvExact((LPSTR)&send_file, sizeof(send_file), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}

	// File Open
	hFile = CreateFile(send_file.cFileName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
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

		return FALSE;
	}

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
		return FALSE;
	}
	else if (ret.type == nFTD_FileContinue)
	{
		if (!RecvExact((LPSTR)&exist_file, sizeof(WIN32_FIND_DATA), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-9 : %d "), GetLastError());
			return FALSE;
		}

		SetFilePointer(hFile, exist_file.nFileSizeLow, (LONG*)&exist_file.nFileSizeHigh, FILE_BEGIN);
		ulExistFileSize.QuadPart = exist_file.nFileSizeLow;
		ulExistFileSize.HighPart = exist_file.nFileSizeHigh;
		ulTemp.QuadPart += ulExistFileSize.QuadPart;
	}

	// file send
	// 
	//0byte ������ ���� �Ʒ��� do~while�� ���� �ʾƾ� �Ѵ�.
	if (ulFileSize.QuadPart == 0)
	{
		logWriteE(_T("0 byte file. just return."));
		CloseHandle(hFile);
		return TRUE;
	}

	//���� ���� ����
	DWORD dwBytesRead;
	LPSTR packet = new CHAR[BUFFER_SIZE];
	DWORD dwStartTicks = GetTickCount();
	ULONGLONG sendedSize = 0;
	int nCompareSpeed = GetPrivateProfileInt(_T("FILE"), _T("SPEED"), 1024000, get_exe_directory() + _T("\\config.ini"));

	//AP2P ����� ���� �ִ� �ӵ��� 1,240,000���� �����Ѵ�.
	//����ڰ� config.ini���� 0���� �����Ҽ��� �����Ƿ� �� ���� 1,240,000���� �����Ѵ�.
	if (g_FT_mode != FT_MODE_AP2P)
	{
		nCompareSpeed = 0;
	}
	else if (nCompareSpeed == 0 || nCompareSpeed > 1024000)
	{
		nCompareSpeed = 1024000;
		WritePrivateProfileString(_T("FILE"), _T("SPEED"), i2S(nCompareSpeed), get_exe_directory() + _T("\\config.ini"));
	}

	logWrite(_T("nCompareSpeed = %d"), nCompareSpeed);

	do
	{
		ReadFile(hFile, packet, BUFFER_SIZE, &dwBytesRead, NULL);

		// 20170404 : �������� ���� ���ϱ��� �þ�� ���� ���� ���ɼ��� �ִ�.
		//            ������ ����ѱ��̸�ŭ�� �����ش�.
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

			CloseHandle(hFile);
			delete[] packet;
			return FALSE;
		}

		// 20170404 : ������ ���̸� ��� ���´��� üũ
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
	} while (dwBytesRead == BUFFER_SIZE);

	CloseHandle(hFile);
	delete[] packet;

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
	//USHORT usLength;
	ULARGE_INTEGER ulSize;
	WIN32_FIND_DATA recv_file;
	ULARGE_INTEGER exist_filesize;
	WIN32_FIND_DATA exist_file;

	//fullpath length ����
	//if (!RecvExact((LPSTR)&usLength, sizeof(USHORT), BLASTSOCK_BUFFER))
	//{
	//	logWriteE(_T("CODE-1 : %d "), GetLastError());
	//	return FALSE;
	//}

	////fullpath ����
	//TCHAR path[MAX_PATH] = { 0, };
	//if (!RecvExact((LPSTR)path, usLength, BLASTSOCK_BUFFER))
	//{
	//	logWriteE(_T("CODE-2 : %d "), GetLastError());
	//	return FALSE;
	//}

	////����ũ�� ����
	//if (!RecvExact((LPSTR)&ulSize, sizeof(ULARGE_INTEGER), BLASTSOCK_BUFFER))
	//{
	//	logWriteE(_T("CODE-3 : %d "), GetLastError());
	//	return FALSE;
	//}

	//WIN32_FIND_DATA ����
	if (!RecvExact((LPSTR)&recv_file, sizeof(WIN32_FIND_DATA), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return FALSE;
	}

	ulSize.HighPart = recv_file.nFileSizeHigh;
	ulSize.LowPart = recv_file.nFileSizeLow;

	CString sPath = convert_special_folder_to_real_path(recv_file.cFileName);
	logWrite(_T("to real path : \"%s\" to \"%s\""), recv_file.cFileName, sPath);


	HANDLE hFile = CreateFile(sPath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		logWriteE(_T("CODE-4 : %d "), GetLastError());

		ret.type = nFTD_ERROR;
		if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-5 : %d "), GetLastError());
			return FALSE;
		}

		//delete[] lpPathName;
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

			//���� ������ ����ũ�⸸ �������� WIN32_FIND_DATA�� ������ �ð������� ǥ���ϵ��� ����.
			HANDLE hFind = FindFirstFile(sPath, &exist_file);
			FindClose(hFind);
			_tcscpy(exist_file.cFileName, sPath);

			exist_filesize.LowPart = GetFileSize(hFile, &(exist_filesize.HighPart));
			//if (!SendExact((LPSTR)&exist_filesize, sizeof(ULARGE_INTEGER), BLASTSOCK_BUFFER))
			if (!SendExact((LPSTR)&exist_file, sizeof(WIN32_FIND_DATA), BLASTSOCK_BUFFER))
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
				ulSize.QuadPart -= exist_filesize.QuadPart;
				SetFilePointer(hFile, 0, NULL, FILE_END);
			}
			else if (ret.type == nFTD_FileOverWrite)
			{
				CloseHandle(hFile);
				hFile = CreateFile(sPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			}
			else if (ret.type == nFTD_FileIgnore)
			{
				CloseHandle(hFile);
				//delete[] lpPathName;
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

	//0byte ������ ���� �Ʒ��� do~while�� ���� �ʾƾ� �Ѵ�.
	if (ulSize.QuadPart == 0)
	{
		CloseHandle(hFile);
		return TRUE;
	}


	// transfer
	DWORD dwBytesRead = BUFFER_SIZE;
	DWORD dwBytesWrite;
	LPSTR packet = new CHAR[BUFFER_SIZE];

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
			delete[] packet;
			return FALSE;
		}
		WriteFile(hFile, packet, dwBytesRead, &dwBytesWrite, NULL);
		ulSize.QuadPart -= dwBytesRead;
	} while (dwBytesRead == BUFFER_SIZE);

	//���۹��� ������ ��¥������ ������ �����ϰ� �����Ѵ�.
	SetFileTime(hFile, &recv_file.ftCreationTime, &recv_file.ftLastAccessTime, &recv_file.ftLastWriteTime);

	//delete[] lpPathName;
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


BOOL CnFTDClientSocket::create_directory(LPCTSTR lpPathName)
{
	msg ret;
	USHORT length;
	TCHAR path[MAX_PATH] = { 0, };
	//LPTSTR PathName = new TCHAR[MAX_PATH];
	//ZeroMemory(PathName, MAX_PATH * sizeof(TCHAR));

	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}
	if (!RecvExact((LPSTR)path, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return FALSE;
	}

	CString sPath = convert_special_folder_to_real_path(path);
	logWrite(_T("to real path : \"%s\" to \"%s\""), path, sPath);


	if (make_full_directory(sPath))
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

	//delete[] PathName;

	if (ret.type == nFTD_OK)
	{
		return TRUE;
	}
	else
	{
		logWriteE(_T("Receive Not OK"));
	}

	return FALSE;
}

BOOL CnFTDClientSocket::Rename(LPCTSTR lpOldName, LPCTSTR lpNewName)
{
	msg ret;
	USHORT length1, length2;
	TCHAR OldPathName[MAX_PATH] = { 0, };
	//ZeroMemory(OldPathName, MAX_PATH * sizeof(TCHAR));
	TCHAR NewPathName[MAX_PATH] = { 0, };
	//ZeroMemory(NewPathName, MAX_PATH * sizeof(TCHAR));

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

	//if (m_FileManager.Rename(OldPathName, NewPathName))
	if (MoveFile(OldPathName, NewPathName))
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
	//delete[] OldPathName;
	//delete[] NewPathName;

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

BOOL CnFTDClientSocket::delete_directory(LPCTSTR lpPath)
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

	if (m_FileManager.delete_directory(PathName))
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

		logWrite(_T("drive. %s"), DriveName);

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

BOOL CnFTDClientSocket::change_directory(LPCTSTR lpDirName)
{
	msg ret;
	USHORT length;
	LPTSTR DirName[MAX_PATH] = { 0, };
	//ZeroMemory(DirName, MAX_PATH * sizeof(TCHAR));
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

	CString path = convert_special_folder_to_real_path((LPCTSTR)DirName);
	logWrite(_T("to real path : \"%s\" to \"%s\""), (LPCTSTR)DirName, path);

	//"�� PC"�� ���� ������ true, �׷��� ������ _tchdir()�� ��� ����.
	if ((path == ::get_system_label(CSIDL_DRIVES)) || (_tchdir(path) == 0))
		ret.type = nFTD_OK;
	else
		ret.type = nFTD_ERROR;

	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return FALSE;
	}

	if (ret.type == nFTD_OK)
	{
		logWrite(_T("change_directory() OK"));
		return TRUE;
	}

	logWriteE(_T("Receive Not OK"));
	return FALSE;
}

BOOL CnFTDClientSocket::TotalSpace(PULARGE_INTEGER lpTotalNumberOfFreeBytes, TCHAR drive)
{
	if (!RecvExact((LPSTR)&drive, sizeof(TCHAR), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}

	msgDiskSpace msgTotalNumberOfFreeBytes;
#ifdef MOBILE_FILETRANSFER
	ULARGE_INTEGER tempSize;
	if (m_FileManager.TotalSpace(&(tempSize)))
		msgTotalNumberOfFreeBytes.type = nFTD_OK;
	else
		msgTotalNumberOfFreeBytes.type = nFTD_ERROR;

	msgTotalNumberOfFreeBytes.space = tempSize.QuadPart;
#else
	msgTotalNumberOfFreeBytes.space.QuadPart = get_disk_total_size(CString(drive));
	if (true)// m_FileManager.TotalSpace(&(msgTotalNumberOfFreeBytes.space)))
		msgTotalNumberOfFreeBytes.type = nFTD_OK;
	else
		msgTotalNumberOfFreeBytes.type = nFTD_ERROR;
#endif

	if (!SendExact((LPSTR)&msgTotalNumberOfFreeBytes, sz_msgDiskSpace, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
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

BOOL CnFTDClientSocket::RemainSpace(PULARGE_INTEGER lpTotalNumberOfRemainBytes, TCHAR drive)
{
	if (!RecvExact((LPSTR)&drive, sizeof(TCHAR), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return FALSE;
	}

	msgDiskSpace msgTotalNumberOfRemainBytes;
#ifdef MOBILE_FILETRANSFER
	ULARGE_INTEGER tempSize;
	if (m_FileManager.RemainSpace(&(tempSize)))
		msgTotalNumberOfRemainBytes.type = nFTD_OK;
	else
		msgTotalNumberOfRemainBytes.type = nFTD_ERROR;
	msgTotalNumberOfRemainBytes.space = tempSize.QuadPart;
#else
	msgTotalNumberOfRemainBytes.space.QuadPart = get_disk_free_size(CString(drive));
	if (true)//m_FileManager.RemainSpace(&(msgTotalNumberOfRemainBytes.space)))
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

BOOL CnFTDClientSocket::get_system_label()
{
	logWrite(_T(" "));

	std::map<int, CString>* map = theApp.m_shell_imagelist.m_volume[0].get_label_map();
	std::map<int, CString>::iterator it = map->begin();

	for (; it != map->end(); it++)
	{
		logWrite(_T("system label. %d = %s"), it->first, it->second);

		//csidl�� ������
		if (!SendExact((LPSTR) & (it->first), sizeof(int), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-1 : %d"), GetLastError());
			return FALSE;
		}

		//�ش��ϴ� ���̺� ���ڿ��� ���̸� ������
		int len = _tcslen(it->second) * 2;
		if (!SendExact((LPSTR)&len, sizeof(int), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d"), GetLastError());
			return FALSE;
		}

		//���� ���ڿ��� ������
		if (!SendExact((LPSTR)(LPCTSTR)(it->second), len, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d"), GetLastError());
			return FALSE;
		}
	}

	int end = -1;
	if (!SendExact((LPSTR)&end, sizeof(int), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d"), GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL CnFTDClientSocket::get_system_path()
{
	std::map<int, CString>* map = theApp.m_shell_imagelist.m_volume[0].get_path_map();
	std::map<int, CString>::iterator it = map->begin();

	for (; it != map->end(); it++)
	{
		logWrite(_T("system path. %d = %s"), it->first, it->second);

		//csidl�� ������
		if (!SendExact((LPSTR) & (it->first), sizeof(int), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-1 : %d"), GetLastError());
			return FALSE;
		}

		//�ش��ϴ� ���ڿ��� ���̸� ������
		int len = _tcslen(it->second) * 2;
		if (!SendExact((LPSTR)&len, sizeof(int), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d"), GetLastError());
			return FALSE;
		}

		//���� ���ڿ��� ������
		if (!SendExact((LPSTR)(LPCTSTR)(it->second), len, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-3 : %d"), GetLastError());
			return FALSE;
		}
	}

	int end = -1;
	if (!SendExact((LPSTR)&end, sizeof(int), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-4 : %d"), GetLastError());
		return FALSE;
	}

	return TRUE;
}

bool CnFTDClientSocket::get_drive_list()
{
	std::deque<CDiskDriveInfo> *drive_list = theApp.m_shell_imagelist.m_volume[0].get_drive_list();
	//::get_drive_list(&drive_list);

	for (auto drive : *drive_list)
	{
		logWrite(_T("type = %d, label = %s, path = %s, total_space = %s, free_space = %s"),
				drive.type, drive.label, drive.path,
				i2S(drive.total_space.QuadPart, true), i2S(drive.free_space.QuadPart, true));

		if (!SendExact((LPSTR)&drive, sizeof(CDiskDriveInfo), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-1 : %d"), GetLastError());
			return false;
		}
	}
	
	CDiskDriveInfo drive_info;
	drive_info.type = DRIVE_UNKNOWN;
	if (!SendExact((LPSTR)&drive_info, sizeof(CDiskDriveInfo), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d"), GetLastError());
		return false;
	}

	return true;
}

/*
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
	_stprintf(path, _T("%s"), get_known_folder(CSIDL_MYDOCUMENTS));

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
*/
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
	// ���� ��θ� ��´�.
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

	LPTSTR PathName = new TCHAR[length + 1];
	ZeroMemory(PathName, (length + 1) * sizeof(TCHAR));

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
	int i;
	//msg ret;
	bool recursive = false;
	USHORT length;
	LPTSTR path[MAX_PATH] = { 0, };

	//path ���� ����
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return false;
	}                                                                                                                                    

	//path ����
	if (!RecvExact((LPSTR)path, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	//recursive ���� ����
	if (!RecvExact((LPSTR)&recursive, sizeof(bool), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d "), GetLastError());
		return false;
	}

	CString sPath = (LPTSTR)path;
	std::deque<WIN32_FIND_DATA> dq;

	//�� PC �� ������ ���� ���� ó��
	if (sPath == theApp.m_shell_imagelist.m_volume[0].get_label(CSIDL_DRIVES))
	{
		for (i = 0; i < theApp.m_shell_imagelist.m_volume[0].get_drive_list()->size(); i++)
		{
			WIN32_FIND_DATA data;
			ZeroMemory(&data, sizeof(data));
			data.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
			_stprintf(data.cFileName, _T("%s"), theApp.m_shell_imagelist.m_volume[0].get_drive_list()->at(i).label);
			logWrite(_T("%s"), data.cFileName);
			//CString drive = convert_special_folder_to_real_path(data.cFileName);
			//ULARGE_INTEGER filesize = get_dis
			//filesize
			dq.push_back(data);
		}
	}
	else
	{
		//sPath�� �Ѿ���� �� �� PC, ���� ȭ��, ����, ���� ��ũ(C:) �� ���� �Ѿ���� ���� ��η� �����ؼ� ���ؾ� �Ѵ�.
		sPath = convert_special_folder_to_real_path((LPTSTR)path);
		logWrite(_T("to real path : \"%s\" to \"%s\""), (LPTSTR)path, sPath);

		find_all_files(sPath, &dq, _T("*"), true, recursive);

		//dot, ���������� ����.
		for (i = dq.size() - 1; i >= 0; i--)
		{
			if (dq[i].dwFileAttributes & FILE_ATTRIBUTE_HIDDEN ||
				_tcscmp(dq[i].cFileName, _T(".")) == 0 ||
				_tcscmp(dq[i].cFileName, _T("..")) == 0)
			{
				dq.erase(dq.begin() + i);
			}
		}
	}

	length = sizeof(WIN32_FIND_DATA);

	for (i = 0; i < dq.size(); i++)
	{
		TRACE(_T("%3d = %s\n"), i, dq[i].cFileName);

		//���ϸ� ����
		if (!SendExact((LPSTR)&dq[i], length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d"), GetLastError());
			return false;
		}
	}

	WIN32_FIND_DATA temp;
	ZeroMemory(&temp, sizeof(temp));

	//�� ��ȣ ����
	if (!SendExact((LPSTR)&temp, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d"), GetLastError());
		return false;
	}

	return true;
}

bool CnFTDClientSocket::folderlist_all()
{
	int i;
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

	CString sPath = path;
	std::deque<WIN32_FIND_DATA> dq;
	std::deque<CDiskDriveInfo> *drive_list = theApp.m_shell_imagelist.m_volume[0].get_drive_list();
	WIN32_FIND_DATA data;
	length = sizeof(WIN32_FIND_DATA);


	//�� PC �� ������ ���� ����̺� ����� �����ϰ�
	if (sPath == theApp.m_shell_imagelist.m_volume[0].get_label(CSIDL_DRIVES))
	{
		for (i = 0; i < drive_list->size(); i++)
		{
			ZeroMemory(&data, sizeof(data));
			data.dwFileAttributes = FILE_ATTRIBUTE_DIRECTORY;
			_stprintf(data.cFileName, _T("%s"), drive_list->at(i).label);
			dq.push_back(data);
		}

		ret.type = nFTD_OK;
	}
	else
	{
		//sPath�� �Ѿ���� �� �� PC, ���� ȭ��, ����, ���� ��ũ(C:) �� ���� �Ѿ���� ���� ��η� �����ؼ� ���ؾ� �Ѵ�.
		sPath = convert_special_folder_to_real_path((LPTSTR)path);
		logWrite(_T("to real path : \"%s\" to \"%s\""), (LPTSTR)path, sPath);

		if (!PathFileExists(sPath) || !PathIsDirectory(sPath))
		{
			//�������� ���� ���
			ret.type = nFTD_ERROR;
		}
		else
		{
			ret.type = nFTD_OK;

			find_all_files(sPath, &dq, _T("*"), true);

			//���丮�� �����. (dot, ��������, �ܼ������� ����)
			for (i = dq.size() - 1; i >= 0; i--)
			{
				//���� ���丮�� �ƴϸ� ����Ʈ���� �����ϰ�
				if (dq[i].dwFileAttributes & FILE_ATTRIBUTE_HIDDEN ||
					!(dq[i].dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
					_tcscmp(dq[i].cFileName, _T(".")) == 0 ||
					_tcscmp(dq[i].cFileName, _T("..")) == 0)
				{
					dq.erase(dq.begin() + i);
				}
				//���丮�� ���� subfolder count���� ��� Ʈ������ Ȯ���ư ǥ�������� �����ϹǷ�
				//nFileSizeLow�� �� ���� �־ �Ѱ��ش�.
				//subfolder�� count�� ���ϴ��� FindFirstFile()�� �̿��ؼ� �����̸� break�ϴ��Ĵ� ��쿡 ���� ������� �ִ�.
				//c:\windows ��� ���� ������ FindFirstFile()�� ���� ���̰� ����ڰ� ���� ������ ���������� ���� ���ϵ鸸 ���ٸ� std::count_if�� ���� ���̴�.
				else
				{
					long t0 = clock();
					int subfolder_count = has_sub_folders(dq[i].cFileName);
					TRACE(_T("elapsed for %s = %ld\n"), dq[i].cFileName, clock() - t0);
					dq[i].nFileSizeLow = subfolder_count;
					/*
					int subfolder_count = 0;

					//namespace fs = std::experimental::filesystem;
					//for (auto& p : fs::directory_iterator(dq[i].cFileName))
					//	subfolder_count++;
					using std::experimental::filesystem::directory_iterator;
					using fp = bool(*)(const std::experimental::filesystem::path&);
					subfolder_count = std::count_if(directory_iterator(dq[i].cFileName), directory_iterator{}, (fp)std::experimental::filesystem::is_directory);
					TRACE(_T("elapsed for %s = %ld\n"), dq[i].cFileName, clock() - t0);
					dq[i].nFileSizeLow = subfolder_count;
					*/
				}
			}
		}
	}

	//�غ� ��� �߽�
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d"), GetLastError());
		return false;
	}

	if (ret.type == nFTD_ERROR)
		return false;

	for (i = 0; i < dq.size(); i++)
	{
		TRACE(_T("%3d = %s\n"), i, dq[i].cFileName);

		//���ϸ� ����
		if (!SendExact((LPSTR)&dq[i], length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d"), GetLastError());
			return false;
		}
	}

	WIN32_FIND_DATA temp;
	ZeroMemory(&temp, sizeof(temp));

	//�� ��ȣ ����
	if (!SendExact((LPSTR)&temp, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d"), GetLastError());
		return false;
	}

	return true;
}

bool CnFTDClientSocket::get_subfolder_count()
{
	USHORT length;
	LPTSTR path = new TCHAR[MAX_PATH];
	ZeroMemory(path, MAX_PATH * sizeof(TCHAR));

	//path ���� ����
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-1 : %d "), GetLastError());
		return false;
	}

	//path ����
	if (!RecvExact((LPSTR)path, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	std::deque<WIN32_FIND_DATA> dq;

	CString sPath = convert_special_folder_to_real_path(path);
	int subfolder_count = 0;

	long t0 = clock();
	if (true)
	{
		namespace fs = std::experimental::filesystem;
		for (auto& p : fs::directory_iterator(sPath.GetBuffer()))
			subfolder_count++;
	}
	else
	{
		//find_all_files()�� ���� ���������� �ӵ��� �ʹ� ����
		find_all_files(sPath, &dq, _T("*"), true);

		for (auto const &item : dq)
		{
			if (!(item.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) &&
				(item.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				subfolder_count++;
		}
	}
	TRACE(_T("elapsed = %ld\n"), clock() - t0);

	//subfolder count ����
	if (!SendExact((LPSTR)&subfolder_count, sizeof(int), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d"), GetLastError());
		return false;
	}

	return true;
}

bool CnFTDClientSocket::new_folder_index()
{
	USHORT length;
	TCHAR path[MAX_PATH] = { 0, };
	TCHAR new_folder_title[MAX_PATH] = { 0, };

	//path ���� ����
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	//path ����
	if (!RecvExact((LPSTR)path, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	//new_folder_title ���� ����
	if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	//new_folder_title ����
	if (!RecvExact((LPSTR)new_folder_title, length, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	int index = get_file_index(path, new_folder_title);
	if (!SendExact((LPSTR)&index, sizeof(int), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-3 : %d"), GetLastError());
		return false;
	}

	return true;
}

bool CnFTDClientSocket::file_command()
{
	msg ret;
	USHORT length;
	int cmd = -1;
	LPTSTR param0[MAX_PATH] = { 0, };
	LPTSTR param1[MAX_PATH] = { 0, };
	CString sParam0;
	CString sParam1;
	std::deque<CString> dq;

	//��� ����
	if (!RecvExact((LPSTR)&cmd, sizeof(int), BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-2 : %d "), GetLastError());
		return false;
	}

	//�Ӽ��� ���������� �� �� �����Ƿ� n���� ���ϸ��� �޴´�.
	if (cmd == file_cmd_property)
	{
		while (true)
		{
			TCHAR fullpath[MAX_PATH] = { 0, };

			//���� ����
			if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-1 : %d "), GetLastError());
				return false;
			}

			if (length == 0)
				break;

			//fullpath ����
			if (!RecvExact((LPSTR)fullpath, length, BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-2 : %d "), GetLastError());
				return false;
			}

			CString sfullpath = convert_special_folder_to_real_path(fullpath);
			logWrite(_T("to real path : \"%s\" to \"%s\""), fullpath, sfullpath);

			dq.push_back(sfullpath);
		}
	}
	else
	{
		//param0 ���� ����
		if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-1 : %d "), GetLastError());
			return false;
		}

		//param0 ����
		if (!RecvExact((LPSTR)param0, length, BLASTSOCK_BUFFER))
		{
			logWriteE(_T("CODE-2 : %d "), GetLastError());
			return false;
		}

		sParam0 = convert_special_folder_to_real_path((LPTSTR)param0);
		logWrite(_T("to real path : \"%s\" to \"%s\""), (LPTSTR)param0, sParam0);

		if (cmd == file_cmd_rename)
		{
			//param1 ���� ����
			if (!RecvExact((LPSTR)&length, sizeof(USHORT), BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-1 : %d "), GetLastError());
				return false;
			}

			//param1 ����
			if (!RecvExact((LPSTR)param1, length, BLASTSOCK_BUFFER))
			{
				logWriteE(_T("CODE-2 : %d "), GetLastError());
				return false;
			}

			sParam1 = (LPTSTR)param1;
			sParam1 = convert_special_folder_to_real_path((LPTSTR)param1);
			logWrite(_T("to real path : \"%s\" to \"%s\""), (LPTSTR)param1, sParam1);
		}
	}

	if (cmd == file_cmd_property)
		logWrite(_T("file_command success. cmd = %d, dq size = %d, dq[0] = %s"), cmd, dq.size(), dq[0]);
	else
		logWrite(_T("cmd = %d, sParam0 = %s, sParam1 = %s\n"), cmd, sParam0, sParam1);

	bool res = false;
	if (cmd == file_cmd_open)
	{
		if (PathFileExists(sParam0))
		{
			ShellExecute(NULL, _T("open"), sParam0, 0, 0, SW_SHOWNORMAL);
			res = true;
		}
	}
	else if (cmd == file_cmd_open_explorer)
	{
		res = true;

		//�� PC�� ���õ� ��� param0�� "�� PC"��� ���� �����µ� �״�� ���� "����" ������ ������.
		//empty�� �������� ����� ���� "�� PC"�� Ž����� ������.
		if (sParam0 == theApp.m_shell_imagelist.m_volume[0].get_label(CSIDL_DRIVES))
			sParam0 = _T("");

		ShellExecute(NULL, _T("open"), _T("explorer"), sParam0, 0, SW_SHOWNORMAL);
	}
	else if (cmd == file_cmd_new_folder)
	{
		res = make_full_directory(sParam0);
	}
	else if (cmd == file_cmd_rename)
	{
		res = MoveFile(sParam0, sParam1);
	}
	else if (cmd == file_cmd_delete)
	{
		res = delete_file(sParam0, true);
	}
	else if (cmd == file_cmd_property)
	{
		//thread���� ȣ���ؼ����� ���⼭ ���� show_property_window()�� �θ��� �����Ѵ�. main���� ȣ���ؾ� �Ѵ�.
		//res = show_property(std::deque<CString> { sParam0 });
		//res = show_property(std::deque<CString> { _T("C:\\") });
		res = true;
		::SendMessage(((CnFTDClientDlg*)AfxGetApp()->GetMainWnd())->m_hWnd, Message_CnFTDClientSocket, (WPARAM)&dq, 0);
	}
	else if (cmd == file_cmd_check_exist)
	{
		res = PathFileExists(sParam0);
	}

	//��� ó�� ��� ����
	ret.type = (res ? nFTD_OK : nFTD_ERROR);
	if (!SendExact((LPSTR)&ret, sz_msg, BLASTSOCK_BUFFER))
	{
		logWriteE(_T("CODE-9 : %d "), GetLastError());
		return false;
	}

	return true;
}
