#pragma once

//20260821 by claude. 숫자 버전 토큰을 문자열로 바꾸기 위한 매크로. .rc 안에서는 int·string 타입을 쓸 수 없다.
//STRINGIZE 가 2단계인 이유 : 1단계만 두면 인자가 전개되기 전에 문자열화되어 "VER_MAJOR" 라는 글자가 그대로 남는다.
#define STRINGIZE2(x) #x
#define STRINGIZE(x) STRINGIZE2(x)

//20260821 by claude. FileVersion 은 구버전 agent 호환 게이팅(is_client_compatible)이 get_file_property() 로
//읽는 값이다. 형식이나 값이 바뀌면 원격 파일전송이 통째로 게이팅에 걸린다.
#define VER_MAJOR	2026
#define VER_MINOR	8
#define VER_PATCH	21
#define VER_BUILD	0

//20260821 by claude. ProductVersion 은 예전부터 FileVersion 과 따로 1.0.0.1 에 머물러 있다. 기존 값을 유지한다.
#define PROD_VER_MAJOR	1
#define PROD_VER_MINOR	0
#define PROD_VER_PATCH	0
#define PROD_VER_BUILD	1

#define FILE_VER VER_MAJOR,VER_MINOR,VER_PATCH,VER_BUILD
#define PROD_VER PROD_VER_MAJOR,PROD_VER_MINOR,PROD_VER_PATCH,PROD_VER_BUILD

#define STR_FILE_VER STRINGIZE(VER_MAJOR) "." STRINGIZE(VER_MINOR) "." STRINGIZE(VER_PATCH) "." STRINGIZE(VER_BUILD)
#define STR_PROD_VER STRINGIZE(PROD_VER_MAJOR) "." STRINGIZE(PROD_VER_MINOR) "." STRINGIZE(PROD_VER_PATCH) "." STRINGIZE(PROD_VER_BUILD)

//20260821 by claude. LMMSE_SERVICE 구성은 LMM_SERVICE 도 함께 정의하므로 LMMSE 를 반드시 먼저 검사해야 한다.
//(nFTDClient.cpp 의 제품 분기와 같은 순서)
#if defined(LMMSE_SERVICE)
	#define PRODUCT_NAME		"LinkMeMineSE"
	#define FILE_DESCRIPTION	"nFTDClient2 for LinkMeMineSE"
#elif defined(_REMOTE_SDK)
	#define PRODUCT_NAME		"RemoteSDK"
	#define FILE_DESCRIPTION	"nFTDClient2 for RemoteSDK"
#elif defined(_ANYSUPPORT)
	#define PRODUCT_NAME		"AnySupport"
	#define FILE_DESCRIPTION	"nFTDClient2 for AnySupport"
#elif defined(LMM_SERVICE)
	#define PRODUCT_NAME		"LinkMeMine"
	#define FILE_DESCRIPTION	"nFTDClient2 for LinkMeMine"
#else
	#define PRODUCT_NAME		"LinkMeMine"
	#define FILE_DESCRIPTION	"nFTDClient2 for LinkMeMine"
#endif

#define COMPANY_NAME		"Koino Co., Ltd."
#define LEGAL_COPY_RIGHT	"Copyright 2026 Koino Corp. All Rights Reserved"
#define INTERNAL_NAME		"nFTDClient2.exe"
#define ORIGINAL_FILENAME	"nFTDClient2.exe"
