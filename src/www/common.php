<?php

define('__TEST_CLIENT_ID__','client_id_111888');
define('__TEST_CLIENT_SECRET__','client_secret_111888');
define('__TEST_USERNAME__','username_111888');
define('__TEST_PASSWORD__','password_111888');

class My_Storage extends HTTP_OAuth2_Storage{

    function selectClient($sKey){
        if($sKey==__TEST_CLIENT_ID__){
            $client=new HTTP_OAuth2_Credential_Client();
            $client->client_id = __TEST_CLIENT_ID__;
            $client->client_secret = __TEST_CLIENT_SECRET__;
            $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_WEBSERVER);
            $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_USERAGENT);
            $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_USERCREDENTIAL);
    //        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_CLIENTCREDENTIAL);
            $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_ASSERTION);
            $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_REFRESHTOKEN);
        }else{
            $client=null;
        }
        return $client;
	}
	function checkClient($sKey,$sSecret){
		return 1;
	}
	function checkUser($sKey,$sSecret){
		return 1;
	}
	function selectVerifier($sKey){
        $client=new HTTP_OAuth2_Credential_Client();
        $user=new HTTP_OAuth2_Credential_User();
        $verifier=new HTTP_OAuth2_Credential_Verifier();
        $client->client_id = __TEST_CLIENT_ID__;
        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_WEBSERVER);
        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_USERAGENT);
        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_USERCREDENTIAL);
//        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_CLIENTCREDENTIAL);
        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_ASSERTION);
        $client->addFlow(HTTP_OAuth2::CLIENT_FLOW_REFRESHTOKEN);
        
        $user->username = __TEST_USERNAME__;
        $verifier->client = $client;
        $verifier->user = $user;
        $code = substr(md5($client->client_id.$user->username),0,8);
        return $verifier;
	}
	function createVerifier(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user){
        $code = substr(md5($client->client_id.$user->username),0,8);
        $verifier=new HTTP_OAuth2_Credential_Verifier();
        $verifier->code = $code;
        return $verifier;
	}
	function createRefreshToken(HTTP_OAuth2_Credential_Client $oCredClient, HTTP_OAuth2_Credential_User $user){
		$sKey='refresh_token_xxxxxxx';
		$oCredToken=new HTTP_OAuth2_Credential_RefreshToken();
		$oCredToken->token = $sKey;
		return $oCredToken;
	}
	function createAccessToken(HTTP_OAuth2_Credential_Client $oCred, HTTP_OAuth2_Credential_User $user){
		$sKey='access_token_xxxxxxx';
		$sSecret='access_token_secret_xxxxxxx';
		$oCredToken=new HTTP_OAuth2_Credential_AccessToken();
		$oCredToken->token = $sKey;
		$oCredToken->secret = $sSecret;
		return $oCredToken;
	}
}

