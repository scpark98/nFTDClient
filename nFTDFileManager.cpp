// nFTDFileManager.cpp: implementation of the CnFTDFileManager class.
//
//////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "nFTDClient.h"
#include "nFTDFileManager.h"

#include "stdio.h"
#include "Shellapi.h"
#include <direct.h>
#include "tchar.h"

#include "Common/Functions.h"

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CnFTDFileManager::CnFTDFileManager()
{
	m_hFindFile = INVALID_HANDLE_VALUE;
}

CnFTDFileManager::~CnFTDFileManager()
{
	if (m_hFindFile != INVALID_HANDLE_VALUE)
		FindClose(m_hFindFile);
}

BOOL CnFTDFileManager::create_directory(LPCTSTR lpPathName)
{
	return ::CreateDirectory(lpPathName, NULL);
}

BOOL CnFTDFileManager::Rename(LPCTSTR lpOldName, LPCTSTR lpNewName)
{
	if (_trename(lpOldName, lpNewName) == 0)
		return TRUE;

	return FALSE;
}

BOOL CnFTDFileManager::delete_directory(LPCTSTR lpPath)
{
	SHFILEOPSTRUCT FileOp;

	LPTSTR lpTemp = new TCHAR[1024]; ZeroMemory(lpTemp, 1024);
#ifndef MOBILE_FILETRANSFER
	CurrentPath(1024, lpTemp);
	_tcscat(lpTemp,_T("\\"));
#endif
	_tcscat(lpTemp, lpPath);

	FileOp.hwnd = NULL;
	FileOp.wFunc = FO_DELETE;
	FileOp.pFrom = lpTemp;
	FileOp.pTo = NULL;
	// FOF_NOCONFIRMATION Respond with "Yes to All" for any dialog box that is displayed. 
	// FOF_NOERRORUI Do not display a user interface if an error occurs.  
	FileOp.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI;
	FileOp.fAnyOperationsAborted = false;
	FileOp.hNameMappings = NULL;
	FileOp.lpszProgressTitle = NULL;
	
	int iRet = SHFileOperation(&FileOp);
	delete [] lpTemp;

	if(iRet == 0) return TRUE; else return FALSE;
}

BOOL CnFTDFileManager::DeleteFile(LPCTSTR lpPathName)
{
	return ::DeleteFile(lpPathName);
}

BOOL CnFTDFileManager::change_directory(LPCTSTR lpDirName)
{
	CString path = theApp.m_shell_imagelist.convert_special_folder_to_real_path(0, lpDirName);
	logWrite(_T("to real path : \"%s\" to \"%s\""), lpDirName, path);

	if (_tchdir(path) == 0)
	{
		TRACE(_T("cur dir = %s\n"), path);
		return TRUE;
	}
	
	return FALSE;
}

BOOL CnFTDFileManager::TotalSpace(PULARGE_INTEGER lpTotalNumberOfFreeBytes)
{
	ULARGE_INTEGER ulAvailable, ulRemain; 

	if(GetDiskFreeSpaceEx(NULL, &ulAvailable, lpTotalNumberOfFreeBytes, &ulRemain) != 0) return TRUE;
	else return FALSE;
}

BOOL CnFTDFileManager::RemainSpace(PULARGE_INTEGER lpTotalNumberOfRemainBytes)
{
	ULARGE_INTEGER ulAvailable, ulTotal; 

	if(GetDiskFreeSpaceEx(NULL, &ulAvailable, &ulTotal, lpTotalNumberOfRemainBytes) != 0) return TRUE;
	else return FALSE;
}

BOOL CnFTDFileManager::CurrentPath(DWORD nBufferLength, LPTSTR lpCurrentPath)
{
	DWORD dwRet = GetCurrentDirectory(nBufferLength, lpCurrentPath);
	if(dwRet <= nBufferLength && dwRet != 0) return TRUE;
	else return FALSE;
}

BOOL CnFTDFileManager::FileList(WIN32_FIND_DATA* pFileInfo, LPCTSTR lpPathName)
{
	DWORD nBufferLength = 1024;
	LPTSTR lpBuffer = new TCHAR[nBufferLength];
	ZeroMemory(lpBuffer, nBufferLength);
	if(lpPathName == NULL){
		GetCurrentDirectory(nBufferLength, lpBuffer);
	} else {
		_tcscpy(lpBuffer, lpPathName);
	}
	
	if(lpBuffer[_tcsclen(lpBuffer)-1] != '\\') _tcscat(lpBuffer, _T("\\"));
	_tcscat(lpBuffer, _T("*.*"));
		
	m_hFindFile = FindFirstFile(lpBuffer, pFileInfo);
	if(m_hFindFile != INVALID_HANDLE_VALUE)
	{
		// 파일의 속성을 여기서 결정한다
		// system file 은 보내지 않는다
		if((pFileInfo->dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM)
			return NextFileList(pFileInfo);
		else
			return TRUE;
	}
	else return FALSE;
}

BOOL CnFTDFileManager::NextFileList(WIN32_FIND_DATA* pFileInfo)
{
	if(m_hFindFile == INVALID_HANDLE_VALUE) return FALSE;

	do {
		if(!FindNextFile(m_hFindFile, pFileInfo))
		{
			FindClose(m_hFindFile);
			return FALSE;
		}
	} while((pFileInfo->dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) == FILE_ATTRIBUTE_SYSTEM);
	return TRUE;
}


BOOL CnFTDFileManager::DriveList(PUINT pDriveType, LPTSTR lpDriveName)
{
	SHFILEINFO shFileInfo;
	TCHAR RootPathName[5];
	ZeroMemory(RootPathName, 5);
	_tcscpy(RootPathName, _T("C:\\"));

	for(m_chDrive = 'A'; m_chDrive <= 'Z'; m_chDrive++)
	{
		RootPathName[0] = m_chDrive;
		*pDriveType = GetDriveType(RootPathName);

		if((*pDriveType != DRIVE_UNKNOWN) && (*pDriveType != DRIVE_NO_ROOT_DIR) && (*pDriveType != DRIVE_RAMDISK))
		{
			SHGetFileInfo(RootPathName, 0, &shFileInfo, sizeof(shFileInfo), 
				SHGFI_DISPLAYNAME | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
			_stprintf(lpDriveName, _T("%s"), shFileInfo.szDisplayName);
			m_chDrive++;
			return TRUE;
		}
	}

	return FALSE;
}

/*
BOOL CnFTDFileManager::DriveList(PUINT pDriveType, LPTSTR lpDriveName)
{
	SHFILEINFOA shFileInfo;
	char RootPathName[5];
	ZeroMemory(RootPathName, 5);
	strcpy(RootPathName, "C:\\");

	for(m_chDrive = 'A'; m_chDrive <= 'Z'; m_chDrive++)
	{
		RootPathName[0] = m_chDrive;
		*pDriveType = GetDriveTypeA(RootPathName);
	
		if((*pDriveType != DRIVE_UNKNOWN) && (*pDriveType != DRIVE_NO_ROOT_DIR) && (*pDriveType != DRIVE_RAMDISK))
		{
			SHGetFileInfoA(RootPathName, 0, &shFileInfo, sizeof(shFileInfo), 
				          SHGFI_DISPLAYNAME | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
			sprintf(lpDriveName, "%s", shFileInfo.szDisplayName);
			m_chDrive++;
			return TRUE;
		}
	}
	
	return FALSE;
}
*/
/*
BOOL CnFTDFileManager::NextDriveList(PUINT pDriveType, LPTSTR lpDriveName)
{
	SHFILEINFOA shFileInfo;
	char RootPathName[5];
	ZeroMemory(RootPathName, 5);
	strcpy(RootPathName, "C:\\");

	for(; m_chDrive <= 'Z'; m_chDrive++)
	{
		RootPathName[0] = m_chDrive;
		*pDriveType = GetDriveTypeA(RootPathName);

		if((*pDriveType != DRIVE_UNKNOWN) && (*pDriveType != DRIVE_NO_ROOT_DIR) && (*pDriveType != DRIVE_RAMDISK))
		{
			SHGetFileInfoA(RootPathName, 0, &shFileInfo, sizeof(shFileInfo), 
				SHGFI_DISPLAYNAME | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
			sprintf(lpDriveName, "%s", shFileInfo.szDisplayName);
			m_chDrive++;
			return TRUE;
		}
	}

	return FALSE;
}
*/

BOOL CnFTDFileManager::NextDriveList(PUINT pDriveType, LPTSTR lpDriveName)
{
	SHFILEINFO shFileInfo;
	TCHAR RootPathName[5];
	ZeroMemory(RootPathName, 5);
	_tcscpy(RootPathName, _T("C:\\"));

	for(; m_chDrive <= 'Z'; m_chDrive++)
	{
		RootPathName[0] = m_chDrive;
		*pDriveType = GetDriveType(RootPathName);
		
		if((*pDriveType != DRIVE_UNKNOWN) && (*pDriveType != DRIVE_NO_ROOT_DIR) && (*pDriveType != DRIVE_RAMDISK))
		{
			SHGetFileInfo(RootPathName, 0, &shFileInfo, sizeof(shFileInfo), 
				          SHGFI_DISPLAYNAME | SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
			_stprintf(lpDriveName, _T("%s"), shFileInfo.szDisplayName);
			m_chDrive++;
			return TRUE;
		}
	}
	
	return FALSE;
}


BOOL CnFTDFileManager::FileSize(LPTSTR lpPathName, ULARGE_INTEGER* ulFileSize)
{
	HANDLE hFile = CreateFile(lpPathName, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile == INVALID_HANDLE_VALUE) return FALSE;
	ulFileSize->LowPart = GetFileSize(hFile, &(ulFileSize->HighPart));
	CloseHandle(hFile);
	return TRUE;
}
