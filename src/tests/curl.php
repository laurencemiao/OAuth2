<?php

$client_id = 'client_id_111888';
$client_secret = 'gX1fBat3bV';

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
//curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Token token="vF9dft4qmT"'));
curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
//curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Digest username="Mufasa",realm="testrealm@host.com",nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",uri="/dir/index.html",qop=auth,nc=00000001,cnonce="0a4f113b",response="6629fae49393a05397450978507c4ef1",opaque="5ccc069c403ebaf9f0171e9517f40e41"'));
curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
$sOut=curl_exec($rCurl);
echo $sOut;
