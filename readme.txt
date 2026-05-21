[빌드환경]
- blastsock과 그 안에 cryptopp와의 빌드호환성 때문에 특정 조건에서는 빌드에 실패한다.
- nFTDServer2
	Debug	: winSDK 8.1, vs2022 ok, vs2019 ok, vs2015 ?
	Release	: winSDK 8.1, vs2022 fail, vs2019 fail, vs2015 ok
- nFTDClient
	Debug	: winSDK 8.1, vs2022 ok, vs2019 ok, vs2015 ok
	Release	: winSDK 8.1, vs2022 fail, vs2019 fail, vs2015 ok

[Client listen parameter]
- 1.0 AP2P listen			: -p dev-ap2p.linkmemine.com 443 1234
- 1.0 FastAPI AP2P listen	: -p 114.108.164.45 443 299529
- 3.0 AP2P listen			: -p 13.125.4.150 443 1234
- client for RemoteSDK		: -p 192.168.0.48 7002 10000001
- P2P						: -l 443

[공용라이브러리 설정]
1. 신규로 프로젝트 빌드할 경우
1) CommonLib.props를 텍스트 편집기로 오픈
2) `<CommonLibRoot>` 값을 본인의 소스 루트 경로로 수정
3) Visual Studio 재시작

2. Common 소스 파일 추가 시
- vcxproj와 vcxproj.filters에서 경로를 매크로로 치환
- vcxproj와 vcxproj.filters의 `Include` 경로가 일치하지 않으면 솔루션 탐색기에 파일이 표시되지 않음

1) 솔루션 탐색기에서 Common 필터 우클릭 → **추가 → 기존 항목** (Shift+Alt+A)
2) `{공용라이브러리러 루트경로}\Common\...` 에서 파일 선택 → 추가
3) VS가 vcxproj에 절대경로로 기록하므로, 텍스트 편집기에서 매크로로 치환

**vcxproj:**
```xml
<!-- VS가 자동 생성 -->
<ClCompile Include="{공용라이브러리러 루트경로}\Common\NewModule\NewFile.cpp" />

<!-- 매크로로 치환 -->
<ClCompile Include="$(CommonLibDir)\NewModule\NewFile.cpp" />
```

**vcxproj.filters:** (솔루션 탐색기 표시를 위해 동일하게 치환)
```xml
<ClCompile Include="$(CommonLibDir)\NewModule\NewFile.cpp">
  <Filter>Common</Filter>
</ClCompile>
```
[수정할 내용]
- AP2P 서버 주소를 domain 주소로 할 경우 접속 불가







