﻿
// nFTDClientDlg.cpp: 구현 파일
//

#include "pch.h"
#include "framework.h"
#include "nFTDClient.h"
#include "nFTDClientDlg.h"
#include "afxdialogex.h"

#include <thread>
#include "../../Common/Functions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

extern HMODULE g_hRes;
extern RSAKey g_rsakey;

// 응용 프로그램 정보에 사용되는 CAboutDlg 대화 상자입니다.

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 대화 상자 데이터입니다.
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 지원입니다.

// 구현입니다.
protected:
	DECLARE_MESSAGE_MAP()
public:
//	afx_msg void OnWindowPosChanged(WINDOWPOS* lpwndpos);
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
//	ON_WM_WINDOWPOSCHANGED()
END_MESSAGE_MAP()


// CnFTDClientDlg 대화 상자



CnFTDClientDlg::CnFTDClientDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NFTDCLIENT_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CnFTDClientDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CnFTDClientDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_WM_WINDOWPOSCHANGED()
	ON_REGISTERED_MESSAGE(Message_CnFTDClientSocket, CnFTDClientDlg::on_message_from_CnFTDClientSocket)
	ON_BN_CLICKED(IDOK, &CnFTDClientDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CnFTDClientDlg::OnBnClickedCancel)
	ON_WM_WINDOWPOSCHANGING()
END_MESSAGE_MAP()


// CnFTDClientDlg 메시지 처리기

BOOL CnFTDClientDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 시스템 메뉴에 "정보..." 메뉴 항목을 추가합니다.

	// IDM_ABOUTBOX는 시스템 명령 범위에 있어야 합니다.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 이 대화 상자의 아이콘을 설정합니다.  응용 프로그램의 주 창이 대화 상자가 아닐 경우에는
	//  프레임워크가 이 작업을 자동으로 수행합니다.
	SetIcon(m_hIcon, TRUE);			// 큰 아이콘을 설정합니다.
	SetIcon(m_hIcon, FALSE);		// 작은 아이콘을 설정합니다.

	// TODO: 여기에 추가 초기화 작업을 추가합니다.
	//RestoreWindowPosition(&theApp, this);

	std::thread t(&CnFTDClientDlg::thread_connect, this);
	t.detach();

	return TRUE;  // 포커스를 컨트롤에 설정하지 않으면 TRUE를 반환합니다.
}

LRESULT	CnFTDClientDlg::on_message_from_CnFTDClientSocket(WPARAM wParam, LPARAM lParam)
{
	std::deque<CString> dq = *(std::deque<CString>*)wParam;
	logWrite(_T("show file property window : %s and total %d files."), dq[0], dq.size());
	show_property_window(dq);
	return 0;
}


void CnFTDClientDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 대화 상자에 최소화 단추를 추가할 경우 아이콘을 그리려면
//  아래 코드가 필요합니다.  문서/뷰 모델을 사용하는 MFC 애플리케이션의 경우에는
//  프레임워크에서 이 작업을 자동으로 수행합니다.

void CnFTDClientDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 그리기를 위한 디바이스 컨텍스트입니다.

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 클라이언트 사각형에서 아이콘을 가운데에 맞춥니다.
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 아이콘을 그립니다.
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// 사용자가 최소화된 창을 끄는 동안에 커서가 표시되도록 시스템에서
//  이 함수를 호출합니다.
HCURSOR CnFTDClientDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CnFTDClientDlg::OnWindowPosChanged(WINDOWPOS* lpwndpos)
{
	CDialogEx::OnWindowPosChanged(lpwndpos);

	// TODO: 여기에 메시지 처리기 코드를 추가합니다.
	SaveWindowPosition(&theApp, this);
}

void CnFTDClientDlg::thread_connect()
{
	if (connect() == false)
		return;

	ShowWindow(SW_MINIMIZE);
	m_client_manager.run();

	CDialog::OnCancel();
}

int CnFTDClientDlg::connect()
{
	// standalone 인지 판단.
	BOOL bIsStandAlone = find_parameter(_T("-standalone"));

	CString cmd = GetCommandLine();
	logWrite(_T("cmd = %s"), cmd);

	for (int i = 0; i < __argc; i++)
	{
		logWrite(_T("param[%d] = %s"), i, __targv[i]);
	}
	/*
	LPSTR _lpCmdLine = new CHAR[strlen(lpCmdLine) + 1];
	ZeroMemory(_lpCmdLine, strlen(lpCmdLine) + 1);
	strcpy(_lpCmdLine, lpCmdLine);
	LPSTR lpToken = strtok(_lpCmdLine, " ");

	while (lpToken != NULL)
	{
		if (!strcmp(lpToken, "-standalone"))
		{
			bIsStandAlone = TRUE;
			break;
		}
		lpToken = strtok(NULL, " ");
	}
	delete[] _lpCmdLine;
	*/

	// 20180208 - pjh
#ifdef LMM_SERVICE
	/*
	neturoSingleton singleton;
	if (!singleton.Init(mutexname) && !bIsStandAlone)
	{
		LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_ALREADYRUN, buffer, 256);
		LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_TITLE, buffer2, 256);
		MessageBox(NULL, buffer, buffer2, 0);
		return 0;
	}
	*/
#endif
#ifdef ANYSUPPORT
	neturoSingleton singleton;
	if (!singleton.Init(mutexname) && !bIsStandAlone)
	{
		LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_ALREADYRUN, buffer, 256);
		LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_TITLE, buffer2, 256);
		MessageBox(NULL, buffer, buffer2, 0);
		return 0;
	}
#endif

	if (!m_client_manager.SetConnection(cmd))
	{
		/*
		LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_RUN1, buffer, 256);
		LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_TITLE, buffer2, 256);
		MessageBox(NULL, buffer, buffer2, 0);
		*/
		return 0;
	}

	logWrite(_T("SetConnection completed."));

	// rsa 키 생성
	neturoCrypto crypt;
	crypt.GenerateRSAKey(1024, g_rsakey.pvk, g_rsakey.pbk);
	logWrite(_T("Crypt"));

	if (!m_client_manager.Connection())
	{
		//LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_RUN2, buffer, 256);
		//LoadString(g_hRes, NFTDCLIENT_IDS_MSGBOX_TITLE, buffer2, 256);
		//MessageBox(NULL, buffer, buffer2, 0);
		AfxMessageBox(_T("m_client_manager.Connection() failed"));
		return 0;
	}
	logWrite(_T("Connection completed."));

	return 1;
}

void CnFTDClientDlg::OnBnClickedOk()
{
}


void CnFTDClientDlg::OnBnClickedCancel()
{
	// TODO: 여기에 컨트롤 알림 처리기 코드를 추가합니다.
	CDialogEx::OnCancel();
}


void CnFTDClientDlg::OnWindowPosChanging(WINDOWPOS* lpwndpos)
{
	CDialogEx::OnWindowPosChanging(lpwndpos);

	// TODO: 여기에 메시지 처리기 코드를 추가합니다.
	lpwndpos->flags &= ~SWP_SHOWWINDOW;
}
