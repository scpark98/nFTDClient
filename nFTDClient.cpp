
// nFTDClient.cpp: 애플리케이션에 대한 클래스 동작을 정의합니다.
//

#include "pch.h"
#include "framework.h"
#include "nFTDClient.h"
#include "nFTDClientDlg.h"

#include "SocketsInitializer.h"
#include "Common/Functions.h"

#include <stdarg.h>

HMODULE g_hRes;
RSAKey g_rsakey;


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CnFTDClientApp

BEGIN_MESSAGE_MAP(CnFTDClientApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CnFTDClientApp 생성

CnFTDClientApp::CnFTDClientApp()
{
	// TODO: 여기에 생성 코드를 추가합니다.
	// InitInstance에 모든 중요한 초기화 작업을 배치합니다.
	m_hMutex = NULL;
}

CnFTDClientApp::~CnFTDClientApp()
{
	if (m_hMutex)
	{
		::ReleaseMutex(m_hMutex);
		m_hMutex = NULL;
	}
}


// 유일한 CnFTDClientApp 개체입니다.

CnFTDClientApp theApp;


// 콘솔 상태 출력 구현.
// AttachConsole(ATTACH_PARENT_PROCESS): cmd에서 직접 실행됐을 때만 그 cmd의 콘솔에
// 붙는다. 다른 프로그램(서비스 등)이 호출한 경우 부모에 콘솔이 없어 실패하며,
// AllocConsole을 쓰지 않으므로 새 창이 뜨지 않는다.
static HANDLE g_console_out = INVALID_HANDLE_VALUE;

void console_init()
{
	if (::AttachConsole(ATTACH_PARENT_PROCESS))
	{
		// CONOUT$ 핸들을 직접 열어 WriteConsoleW로 UTF-16을 그대로 쓴다.
		// _vtprintf(=vwprintf)는 CRT 로케일로 wide→멀티바이트 변환을 하는데
		// 기본 "C" 로케일이 한글을 못 바꿔 한글이 누락되므로 CRT를 우회한다.
		g_console_out = ::CreateFile(_T("CONOUT$"), GENERIC_WRITE, FILE_SHARE_WRITE,
									 NULL, OPEN_EXISTING, 0, NULL);
	}
}

void console_status(LPCTSTR fmt, ...)
{
	if (g_console_out == INVALID_HANDLE_VALUE)
		return;

	TCHAR buf[1024];
	va_list args;
	va_start(args, fmt);
	_vsntprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
	va_end(args);
	_tcscat_s(buf, _T("\r\n"));

	DWORD written = 0;
	::WriteConsole(g_console_out, buf, (DWORD)_tcslen(buf), &written, NULL);
}

void console_done()
{
	if (g_console_out == INVALID_HANDLE_VALUE)
		return;

	::CloseHandle(g_console_out);
	g_console_out = INVALID_HANDLE_VALUE;

	// GUI 서브시스템이라 cmd는 실행 즉시 프롬프트를 찍고 이미 입력 대기 상태다.
	// 우리 출력은 그 프롬프트 뒤에 붙으므로 화면상 프롬프트가 사라진 것처럼 보인다.
	// 콘솔 입력 버퍼에 Enter를 넣어 cmd가 프롬프트를 새로 그리게 한다.
	HANDLE in = ::CreateFile(_T("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
							 NULL, OPEN_EXISTING, 0, NULL);
	if (in != INVALID_HANDLE_VALUE)
	{
		INPUT_RECORD rec[2] = {};
		for (int i = 0; i < 2; i++)
		{
			rec[i].EventType = KEY_EVENT;
			rec[i].Event.KeyEvent.bKeyDown = (i == 0);
			rec[i].Event.KeyEvent.wRepeatCount = 1;
			rec[i].Event.KeyEvent.wVirtualKeyCode = VK_RETURN;
			rec[i].Event.KeyEvent.wVirtualScanCode = (WORD)::MapVirtualKey(VK_RETURN, MAPVK_VK_TO_VSC);
			rec[i].Event.KeyEvent.uChar.UnicodeChar = _T('\r');
		}

		DWORD count = 0;
		::WriteConsoleInput(in, rec, 2, &count);
		::CloseHandle(in);
	}

	::FreeConsole();
}


// CnFTDClientApp 초기화

BOOL CnFTDClientApp::InitInstance()
{
	m_hMutex = ::CreateMutex(NULL, FALSE, _T("MUTEX_OF_nFTDClient2"));
	if (::GetLastError() == ERROR_ALREADY_EXISTS)
		return FALSE;

	// 애플리케이션 매니페스트가 ComCtl32.dll 버전 6 이상을 사용하여 비주얼 스타일을
	// 사용하도록 지정하는 경우, Windows XP 상에서 반드시 InitCommonControlsEx()가 필요합니다.
	// InitCommonControlsEx()를 사용하지 않으면 창을 만들 수 없습니다.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// 응용 프로그램에서 사용할 모든 공용 컨트롤 클래스를 포함하도록
	// 이 항목을 설정하십시오.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();

	console_init();
	console_status(_T("\n[nFTDClient2] started : %s"), GetCommandLine());

	AfxEnableControlContainer();

	// 대화 상자에 셸 트리 뷰 또는
	// 셸 목록 뷰 컨트롤이 포함되어 있는 경우 셸 관리자를 만듭니다.
	CShellManager *pShellManager = new CShellManager;

	// MFC 컨트롤의 테마를 사용하기 위해 "Windows 원형" 비주얼 관리자 활성화
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// 표준 초기화
	// 이들 기능을 사용하지 않고 최종 실행 파일의 크기를 줄이려면
	// 아래에서 필요 없는 특정 초기화
	// 루틴을 제거해야 합니다.
	// 해당 설정이 저장된 레지스트리 키를 변경하십시오.
	// TODO: 이 문자열을 회사 또는 조직의 이름과 같은
	// 적절한 내용으로 수정해야 합니다.
	SetRegistryKey(_T("Koino"));

#if defined(LMMSE_SERVICE)
	gLog.set(get_known_folder(CSIDL_COMMON_DOCUMENTS) + _T("\\LinkMeMineSE\\Log\\FileTransfer"), get_exe_file_title());
#elif defined(_REMOTE_SDK)
	gLog.set(get_known_folder(CSIDL_COMMON_DOCUMENTS) + _T("\\Koino\\Log\\FileTransfer"), get_exe_file_title());
#elif defined(_ANYSUPPORT)
	gLog.set(get_known_folder(CSIDL_COMMON_DOCUMENTS) + _T("\\Koino\\Log\\FileTransfer"), get_exe_file_title());
#else
	gLog.set(get_known_folder(CSIDL_COMMON_DOCUMENTS) + _T("\\LinkMeMine\\Log\\FileTransfer"), get_exe_file_title());
#endif

	gLog.write_start_log();

	logWrite(_T("cmdline = %s"), GetCommandLine());

	if (__argc < 3)
	{
		logWrite(_T("Parameters must be at least three. current __argc = %d. exit."), __argc);
		return FALSE;
	}

	// 소켓초기화
	SocketsInitializer socketsInitializer;

	CnFTDClientDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: 여기에 [확인]을 클릭하여 대화 상자가 없어질 때 처리할
		//  코드를 배치합니다.
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: 여기에 [취소]를 클릭하여 대화 상자가 없어질 때 처리할
		//  코드를 배치합니다.
	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "경고: 대화 상자를 만들지 못했으므로 애플리케이션이 예기치 않게 종료됩니다.\n");
		TRACE(traceAppMsg, 0, "경고: 대화 상자에서 MFC 컨트롤을 사용하는 경우 #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS를 수행할 수 없습니다.\n");
	}

	// 위에서 만든 셸 관리자를 삭제합니다.
	if (pShellManager != nullptr)
	{
		delete pShellManager;
	}

#if !defined(_AFXDLL) && !defined(_AFX_NO_MFC_CONTROLS_IN_DIALOGS)
	ControlBarCleanUp();
#endif

	// 대화 상자가 닫혔으므로 응용 프로그램의 메시지 펌프를 시작하지 않고 응용 프로그램을 끝낼 수 있도록 FALSE를
	// 반환합니다.
	return FALSE;
}



int CnFTDClientApp::ExitInstance()
{
	// TODO: 여기에 특수화된 코드를 추가 및/또는 기본 클래스를 호출합니다.
	//gLog.write_end_log();

	console_status(_T("[nFTDClient2] exit"));
	console_done();

	return CWinApp::ExitInstance();
}
