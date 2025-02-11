#pragma once

#include "blastsock.h"

#include "nFTDFileManager.h"
#include "../nFTDServer/nFTDProtocol.h"

#define CONNECTION_CONNECT	0	
#define CONNECTION_LISTEN	1

static const UINT Message_CnFTDClientSocket = ::RegisterWindowMessage(_T("MessageString_CnFTDClientSocket"));

class CnFTDClientSocket : public blastsock
{
public:
	CnFTDClientSocket();
	virtual ~CnFTDClientSocket();

	bool	show_property(std::deque<CString> dq);

	BOOL create_directory(LPCTSTR lpPathName);

	//열기(open), 이름변경(rename), 삭제(delete), 속성보기(property) 등의 파일명령은 파라미터만 다를 뿐이므로 하나의 함수로 통일한다.
	bool file_command();

	bool	new_folder_index();

	BOOL Rename(LPCTSTR lpOldName, LPCTSTR lpNewName);
	BOOL delete_directory(LPCTSTR lpPath);
	BOOL DeleteFile(LPCTSTR lpPathName);
	BOOL change_directory(LPCTSTR lpDirName);

	//drive = 0이면 GetCurrentDirectory()의 디스크 용량
	BOOL TotalSpace(PULARGE_INTEGER lpTotalNumberOfFreeBytes, TCHAR drive = 0);
	//drive = 0이면 GetCurrentDirectory()의 디스크 용량
	BOOL RemainSpace(PULARGE_INTEGER lpTotalNumberOfRemainBytes, TCHAR drive = 0);
	BOOL CurrentPath(DWORD nBufferLength, LPTSTR lpCurrentPath);

	BOOL FileList(WIN32_FIND_DATA* pFileInfo);
	BOOL FileList2(WIN32_FIND_DATA* pFileInfo); // 시작폴더를 받는다.
	BOOL NextFileList(WIN32_FIND_DATA* pFileInfo);
	BOOL DriveList(PUINT pDriveType, LPSTR lpDriveName);
	BOOL NextDriveList(PUINT pDriveType, LPSTR lpDriveName);
	BOOL FileSize(LPTSTR lpPathName, ULARGE_INTEGER* ulFileSize);

	bool	filelist_all();
	bool	folderlist_all();
	bool	get_subfolder_count();

	BOOL Connection();
	BOOL SendFile(LPCTSTR lpFromPathName, LPCTSTR lpToPathName, ULARGE_INTEGER& ulFileSize);
	BOOL RecvFile(LPCTSTR lpFromPathName, LPCTSTR lpToPathName, ULARGE_INTEGER& ulFileSize);
	void SetSockAddr(ULONG addr, USHORT port, int iServerNum, BOOL bIsN2NConnectionTiming);
	void SetConnection(DWORD dwConnection);

	BOOL get_system_label();
	BOOL get_system_path();
	bool get_drive_list();

	BOOL ExecuteFile();
	BOOL FileInfo(WIN32_FIND_DATA* pFileInfo);
	BOOL FileList3(WIN32_FIND_DATA* pFileInfo);

protected:
	CnFTDFileManager m_FileManager;
	DWORD m_dwConnection;
	ULONG m_addr;
	USHORT m_port;
	int m_iServerNum;
	BOOL m_bIsN2NConnectionTiming;
};

