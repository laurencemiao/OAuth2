<?php

$__CUR_DIR__=dirname(__FILE__);
require_once "$__CUR_DIR__/common.php";

require_once "HTTP/OAuth2/Request.php";
require_once "HTTP/OAuth2/Authorization/Client.php";

$client_id = __OAUTH2_TEST_CLIENT_ID__;
$encoded_client_id = urlencode($client_id);
$client_secret = __OAUTH2_TEST_CLIENT_SECRET__;
$encoded_client_secret = urlencode($client_secret);
$client=new HTTP_OAuth2_Authorization_Client();
$client->id=$client_id;
$client->secret=$client_secret;
$username=__OAUTH2_TEST_USER_ID__;
$password=__OAUTH2_TEST_USER_SECRET__;
$redirect_uri = __OAUTH2_TEST_REDIRECT_URI__;
$encoded_redirect_uri = urlencode($redirect_uri);

function read_keyboard($msg){
    $txt=<<<EOT
$msg
-------------------------------------------------------------------
> 
EOT;
    echo $txt;
    $line = trim(fgets(STDIN));
    return $line;
}

function get_redirect($txt){
    $lines=explode("\n",$txt);
    foreach($lines as $line){
        if(empty($line))continue;
        if(0===strpos($line,"Location: "))
            return substr($line,strlen("Location: "));
    }
    return "";
}

function request($uri,$data = "",$headers = array()){
    $curl=curl_init();
    curl_setopt($curl,CURLOPT_URL,$uri);
    curl_setopt($curl,CURLOPT_VERBOSE,0);
    curl_setopt($curl,CURLOPT_HEADER,1);
    curl_setopt($curl,CURLINFO_HEADER_OUT,1);
    curl_setopt($curl,CURLOPT_RETURNTRANSFER,1);
    curl_setopt($curl,CURLOPT_HTTPHEADER,$headers);
    
    if(empty($data))$method = "GET";
    else $method = "POST";
    switch(strtoupper($method)){
        case 'POST':
            curl_setopt($curl,CURLOPT_POST,1);
            curl_setopt($curl,CURLOPT_POSTFIELDS,$data);
            break;
        default:
            curl_setopt($curl,CURLOPT_HTTPGET,1);
    }
    $out=curl_exec($curl);
    return $out;
}

$main_menu=<<<EOT
please enter your choice, QUIT if empty string entered:\n
  0. QUIT, 1. Authorization Code 2. Implicit Grant, 3. Owner Password, 4. Client\n
EOT;
while($line = read_keyboard($main_menu)){
    $choice=intval($line);
    switch($choice){
        case 0:
            exit();
            break;
        case 1:
            test_auth_code();
            break;
        case 2:
            test_user_agent();
            break;
        case 3:
            test_native();
            break;
        case 4:
            test_autonomous();
            break;
        default:
            echo "wrong number!\n\n";
    }
}


function test_auth_code(){
    global $client,$client_id,$client_secret,$encoded_client_id,$encoded_client_secret,$redirect_uri,$encoded_redirect_uri;

    $line=read_keyboard("Client Credentials transfer through FORM or HTTP Basic Authentication Scheme?\n  1. FORM(default),  2. HTTP Basic");

    $oRequest = new HTTP_OAuth2_Request();

    $client_http_basic = 0;
    if($line == 2){
        $client_http_basic = 1;
    }

    if($client_http_basic){
        $headers=array(
            'Authorization: Basic '.base64_encode("$client_id:$client_secret"),
            );
    }else{
        $headers=array();
    }
    $authorize_url=__OAUTH2_TEST_ENDPOINT_AUTHORIZE__."?response_type=code&client_id=$encoded_client_id&redirect_uri=$encoded_redirect_uri&state=test_auth_code";
    $response=request($authorize_url);
    $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
    echo $txt;
    $redirect=get_redirect($txt);
    if($redirect){
        $txt=<<<EOT
Location: $redirect\n
Follow redirect? (Y/n)
EOT;

        $line = read_keyboard($txt);
        if($line != 'n'){
            $response=request($redirect,'',$headers);
            $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
            echo $txt;
        }
        $line = read_keyboard("Then, if you give me the Authorization Code, I will give you the Access Token");
        $token_uri=__OAUTH2_TEST_ENDPOINT_TOKEN__;
        $data=array(
			"grant_type"=>"authorization_code",
			"code"=>$line,
			"redirect_uri"=>$redirect_uri,
			);
		$oRequest->setUrl($token_uri);
		$oRequest->setParameters($data);
		$oRequest->setClientCredential($client);
		$oResponse = $oRequest->send();
		$request=$oRequest->getBody();
		$headers=$oResponse->getHeader();
		$response="HTTP/".$oResponse->getVersion()." ".$oResponse->getStatus()." ".$oResponse->getReasonPhrase()."\n";
		foreach($headers as $key=>$val){
			$response.="$key: $val\n";
		}
		$response.=$oResponse->getBody();
        $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
        echo $txt;
        
    }else{
        $txt=<<<EOT
No redirection detected, anything wrong?
-------------------------------------------------------------------

EOT;
        echo $txt;
    }
}

function test_user_agent(){
    global $client_id,$client_secret,$encoded_client_id,$encoded_client_secret,$encoded_redirect_uri;

    $line=read_keyboard("Client Credentials transfer through FORM or HTTP Basic Authentication Scheme?\n  1. FORM(default),  2. HTTP Basic");

    $client_http_basic = 0;
    if($line == 2){
        $client_http_basic = 1;
    }

    if($client_http_basic){
        $headers=array(
            'Authorization: Basic '.base64_encode("$client_id:$client_secret"),
            );
    }else{
        $headers=array();
    }

    $authorize_url=__OAUTH2_TEST_ENDPOINT_AUTHORIZE__."?type=user_agent&client_id=$encoded_client_id&redirect_uri=$encoded_redirect_uri&state=test_user_agent";
    $response=request($authorize_url);
    $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
    echo $txt;
    $redirect=get_redirect($txt);
    if($redirect){
        $txt=<<<EOT
Location: $redirect\n
Follow redirect? (Y/n)
EOT;

        $line = read_keyboard($txt);
        if($line != 'n'){
            $response=request($redirect);
            $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
            echo $txt;
        }
    }else{
        $txt=<<<EOT
No redirection detected, anything wrong?\n
-------------------------------------------------------------------

EOT;
        echo $txt;
    }
}

function test_native(){
    global $client_http_basic,$username,$password,$client_id,$client_secret,$encoded_client_id,$encoded_client_secret,$encoded_redirect_uri;

    $line=read_keyboard("User Credentials transfer through FORM or HTTP Basic Authentication Scheme?\n  1. FORM(default),  2. HTTP Basic");

    $user_http_basic = 0;
    if($line == 2){
        $user_http_basic = 1;
    }

    if($user_http_basic){
        $headers=array(
            'Authorization: Basic '.base64_encode("$username:$password"),
            );
    }else{
        $headers=array();
    }
    
    $token_uri=__OAUTH2_TEST_ENDPOINT_TOKEN__;
    if($user_http_basic){
        $data="grant_type=user_basic_credentials&client_id=$encoded_client_id&client_secret=$encoded_client_secret";
    }else{
        $data="grant_type=user_basic_credentials&client_id=$encoded_client_id&client_secret=$encoded_client_secret&username=$username&password=$password";
    }
    $response=request($token_uri,$data,$headers);
    $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
    echo $txt;

}

function test_autonomous(){
    global $client_id,$client_secret,$encoded_client_id,$encoded_client_secret,$encoded_redirect_uri;

    $line=read_keyboard("Client Credentials transfer through FORM or HTTP Basic Authentication Scheme?\n  1. FORM(default),  2. HTTP Basic");

    $client_http_basic = 0;
    if($line == 2){
        $client_http_basic = 1;
    }

    if($client_http_basic){
        $headers=array(
            'Authorization: Basic '.base64_encode("$client_id:$client_secret"),
            );
    }else{
        $headers=array();
    }
    
    $token_uri=__OAUTH2_TEST_ENDPOINT_TOKEN__;
    if($client_http_basic){
        $data="grant_type=none";
    }else{
        $data="grant_type=none&client_id=$encoded_client_id&client_secret=$encoded_client_secret";
    }
    $response=request($token_uri,$data,$headers);
    $txt=<<<EOT
-------------------------------------------------------------------
Response:
-----------------------------
$response
-------------------------------------------------------------------

EOT;
    echo $txt;

}

    
