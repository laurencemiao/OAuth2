<?php
$sUrl='http://localhost/authorize.php?type=web_server&client_id=s6BhdRkqt3&redirect_uri=http%3A%2F%2Flocalhost%2Foauth2test%2Fcb.php';
$sUrl='http://localhost/token.php?type=web_server&client_id=s6BhdRkqt3&client_secret=gX1fBat3bV&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb';
$sUrl='http://localhost/token.php';
$aData=array(
	'type'=>'client_credentials',
	'client_id'=>'111888',
	'client_secret'=>'gX1fBat3bV',
	'code'=>'i1WsRn1uB1',
	'redirect_uri'=>'https%3A%2F%2Fclient.example.com%2Fcb',
	);
$sData='client_id=client_id_111888&client_secret=gX1fBat3bV&code=i1WsRn1uB1&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb';
$sData='client_id=client_id_111888&client_secret=gX1fBat3bV&username=username_111888&password=password_111888';
$sData='username=username_111888&password=password_111888';
//$sData=json_encode($aData);

$rCurl=curl_init();
curl_setopt($rCurl,CURLOPT_URL,$sUrl);
curl_setopt($rCurl,CURLOPT_VERBOSE,1);
curl_setopt($rCurl,CURLOPT_POST,1);
//curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Content-type: application/json'));
curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Token token="vF9dft4qmT"'));
curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW'));
curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
$sOut=curl_exec($rCurl);
echo $sOut;
