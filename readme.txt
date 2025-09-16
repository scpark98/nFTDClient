[빌드환경]
- blastsock과 그 안에 cryptopp와의 빌드호환성 때문에 특정 조건에서는 빌드에 실패한다.
- nFTDServer2
	Debug	: winSDK 8.1, vs2022 ok, vs2019 ok, vs2015 ?
	Release	: winSDK 8.1, vs2022 fail, vs2019 fail, vs2015 ok
- nFTDClient
	Debug	: winSDK 8.1, vs2022 ok, vs2019 ok, vs2015 ok
	Release	: winSDK 8.1, vs2022 fail, vs2019 fail, vs2015 ok

[Client listen parameter]
- 1.0 AP2P listen		: -p 3.35.127.253 443 1234
- 3.0 AP2P listen		: -p 13.125.4.150 443 1234
- client for RemoteSDK	: -p 192.168.0.48 7002 10000001

[수정할 내용]
- AP2P 서버 주소를 domain 주소로 할 경우 접속 불가

