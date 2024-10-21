// nFTDFileManager.h: interface for the CnFTDFileManager class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_NFTDFILEMANAGER_H__91E468A3_37DF_4001_80EE_C30477AADDF3__INCLUDED_)
#define AFX_NFTDFILEMANAGER_H__91E468A3_37DF_4001_80EE_C30477AADDF3__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CnFTDFileManager
{
public:
	CnFTDFileManager();
	virtual ~CnFTDFileManager();

	BOOL CreateDirectory(LPCTSTR lpPathName);
	BOOL Rename(LPCTSTR lpOldName, LPCTSTR lpNewName);
	BOOL DeleteDirectory(LPCTSTR lpPath);
	BOOL DeleteFile(LPCTSTR lpPathName);
	BOOL ChangeDirectory(LPCTSTR lpDirName);
	BOOL TotalSpace(PULARGE_INTEGER lpTotalNumberOfFreeBytes);
	BOOL RemainSpace(PULARGE_INTEGER lpTotalNumberOfRemainBytes);
	BOOL CurrentPath(DWORD nBufferLength, LPTSTR lpCurrentPath);
	BOOL FileSize(LPTSTR lpPathName, ULARGE_INTEGER* ulFileSize);

	BOOL FileList(WIN32_FIND_DATA* pFileInfo, LPCTSTR lpPathName = NULL); // lpPathName기준으로 파일정보를 얻어 온다, lpPathName가 NULL이면 GetCurrentDirectory를 호출하여 얻어온 폴더를 기준으로 한다.
	BOOL NextFileList(WIN32_FIND_DATA* pFileInfo);
	BOOL DriveList(PUINT pDriveType, LPTSTR lpDriveName);
	BOOL NextDriveList(PUINT pDriveType, LPTSTR lpDriveName);
protected:
	HANDLE m_hFindFile;
	CHAR m_chDrive;
};

#endif // !defined(AFX_NFTDFILEMANAGER_H__91E468A3_37DF_4001_80EE_C30477AADDF3__INCLUDED_)
