<?php

require_once 'HTTP/OAuth2/Server/Storage.php';
require_once 'HTTP/OAuth2/Server/Storage/Abstract.php';

//define('__OAUTH2_TEST_TMP_DIR__','/tmp/oauth2/');
define('__OAUTH2_TEST_TMP_DIR__','c:\\temp\\oauth2\\');

class HTTP_OAuth2_Server_Storage_Mock extends HTTP_OAuth2_Server_Storage_Abstract{

	function init(){
		if(!is_dir(__OAUTH2_TEST_TMP_DIR__))
			mkdir(__OAUTH2_TEST_TMP_DIR__);
	}
	function fini(){
        $files = glob(__OAUTH2_TEST_TMP_DIR__."/*");
        foreach($files as $file){
            unlink($file);
        }
		rmdir(__OAUTH2_TEST_TMP_DIR__);
	}
	function createAuthorization($client_id, $key = null, $key_type = null){
		$auth=new HTTP_OAuth2_Authorization();
		$auth->client_id = $client_id;
		$auth->key = $key;
		$auth->key_type = $key_type;
		$auth->id = md5("$client_id-$key-$key_type");
		$tmpfname = __OAUTH2_TEST_TMP_DIR__."authorization_$auth->id";
		file_put_contents($tmpfname,serialize($auth));
		clearstatcache();

		return $auth;
	}
	function deleteAuthorization($client_id, $key = null, $key_type = null){
        $auth_id=md5("$client_id-$key-$key_type");
		if(is_file(__OAUTH2_TEST_TMP_DIR__.'/authorization_'.$auth_id)){
			unlink(__OAUTH2_TEST_TMP_DIR__.'/authorization_'.$auth_id);
			clearstatcache();

		}
	}
	function selectAuthorization($client_id, $key = null, $key_type = null){
        $auth_id=md5("$client_id-$key-$key_type");
		$auth=null;
		if(is_file(__OAUTH2_TEST_TMP_DIR__.'/authorization_'.$auth_id)){
			$data = file_get_contents(__OAUTH2_TEST_TMP_DIR__.'/authorization_'.$auth_id);
		}else{
			$data = '';
		}
        if(!empty($data))$auth = unserialize($data);
        return $auth;
	}
    function checkAuthorization(HTTP_OAuth2_Token_Authorization $authen){}

    function selectClient($sKey){
        $client=null;
		if(is_file(__OAUTH2_TEST_TMP_DIR__.'/'.$sKey)){
			$data = file_get_contents(__OAUTH2_TEST_TMP_DIR__.'/'.$sKey);
		}else{
			$data = '';
		}
        if(!empty($data))$client = unserialize($data);
        return $client;
	}
	function deleteClient($client_id){}
	function createClient(HTTP_OAuth2_Credential_Client $client){
        $client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE);
        $client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC);
        $client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION);
        $client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN);
        $client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE);
		$tmpfname = __OAUTH2_TEST_TMP_DIR__.$client->client_id;
		file_put_contents($tmpfname,serialize($client));
		clearstatcache();

		return $client;
	}
    function checkAccessToken(HTTP_OAuth2_Credential_AccessToken $access_token){}

    function selectAuthorizationCode($code){
        $verifier=null;
        if(is_file(__OAUTH2_TEST_TMP_DIR__.'/'.$code)){
            $data = file_get_contents(__OAUTH2_TEST_TMP_DIR__.'/'.$code);
        }else{
            $data = '';
        }
        if(!empty($data))$verifier = unserialize($data);
        return $verifier;
    }
    function createAuthorizationCode(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user){
        $code = substr(md5($client->client_id.$user->username.microtime(1)),0,8);
        $verifier=new HTTP_OAuth2_Token_AuthorizationCode();
        $verifier->code = $code;
        $verifier->user = $user;
        $verifier->client = $client;
        $tmpfname = __OAUTH2_TEST_TMP_DIR__.$code;
        file_put_contents($tmpfname,serialize($verifier));
        clearstatcache();
        return $verifier;
    }
    function deleteAuthorizationCode($code){}
    function checkAuthorizationCode(HTTP_OAuth2_Token_AuthorizationCode $verifier){
        return 1;
    }

    function checkRefreshToken(HTTP_OAuth2_Credential_RefreshToken $refresh_token){}

	function checkClient(HTTP_OAuth2_Credential_Client $client){
		return 1;
	}
	function checkUser(HTTP_OAuth2_Credential_User $user){
		return 1;
	}

    
	function deleteVerifier($code){}


	function selectRefreshToken($refresh_token){}
	function createRefreshToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user){
		$token=new HTTP_OAuth2_Token_RefreshToken();
		$token->token = md5($client->client_id.$user->username.microtime(1));
		$tmpfname = tempnam(__OAUTH2_TEST_TMP_DIR__, "refresh_token_");
		file_put_contents($tmpfname,serialize($token));
		return $token;
	}
	function deleteRefreshToken($refresh_token){}


	function selectAccessToken($access_token){}
	function createAccessToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user){
		$token=new HTTP_OAuth2_Token_AccessToken();
		$token->token = md5($client->client_id.$user->username.microtime(1));
		$token->secret = md5($client->client_id.$user->username.microtime(1).uniqid());
		$tmpfname = tempnam(__OAUTH2_TEST_TMP_DIR__, "access_token_");
		file_put_contents($tmpfname,serialize($token));

		return $token;
	}
	function deleteAccessToken($access_token){}



    function selectUser($sKey){
        $user=null;
		if(is_file(__OAUTH2_TEST_TMP_DIR__.'/'.$sKey)){
			$data = file_get_contents(__OAUTH2_TEST_TMP_DIR__.'/'.$sKey);
		}else{
			$data = '';
		}
        if(!empty($data))$user = unserialize($data);
        return $user;
	}
	function createUser(HTTP_OAuth2_Credential_User $user){
		$tmpfname = __OAUTH2_TEST_TMP_DIR__.$user->username;
		file_put_contents($tmpfname,serialize($user));
		clearstatcache();

		return $user;
	}
	function deleteUser($username){}
}

