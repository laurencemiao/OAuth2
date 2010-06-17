<?php

$__CUR_DIR__ = dirname(__FILE__);
require_once "$__CUR_DIR__/../common.php";
require_once 'HTTP/OAuth2/Server/Storage/Mock.php';
require_once 'PHPUnit/Framework.php';
 
class Token_EndPoint extends PHPUnit_Framework_TestCase
{
	private $_store = null;
	private $_client = null;
	private $_user = null;
	private $_verifier = null;
	private $_verifier1 = null;

	public function setUp(){
		$this->_store = new HTTP_OAuth2_Server_Storage_Mock();
		$this->_store->init(__OAUTH2_TEST_TEMP_DIR__);
		$this->_client = new HTTP_OAuth2_Credential_Client();

		$this->_client->id = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'client_'.uniqid();
		$this->_client->secret = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'client_'.md5(uniqid());

		$this->_store->createClient($this->_client);

		$this->_user = new HTTP_OAuth2_Credential_User();

		$this->_user->username = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'user_'.uniqid();
		$this->_user->password = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'user_'.md5(uniqid());

		$this->_store->createUser($this->_user);

		$verifier = new HTTP_OAuth2_Token_AuthorizationCode();
		$verifier->client_id = $this->_client->id;
		$verifier->username = $this->_user->username;
		$verifier->redirect_uri = __OAUTH2_TEST_UNIT_CALLBACK__;

		$this->_verifier = $this->_store->createAuthorizationCode($verifier);
		$this->_verifier1 = $this->_store->createAuthorizationCode($verifier);
	}

    public function testVerificationValidCode()
    {
		$client_id = $this->_client->id;
		$client_secret = $this->_client->secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
//		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'grant_type'=>'authorization_code',
			'client_id'=>$this->_client->id,
			'client_secret'=>$this->_client->secret,
			'code'=>$this->_verifier->code,
			'redirect_uri'=>__OAUTH2_TEST_UNIT_CALLBACK__,
			);
		$sData = '';
		foreach($aData as $key=>$val){
			$sData.="&$key=$val";
		}

		$sData=substr($sData,1);
		
		curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
		$ret = curl_exec($rCurl);
		$info=curl_getinfo($rCurl);
		$this->assertTrue($info['http_code']==302, 'response status code should be 302');

    }

    public function testVerificationInvalidCode()
	{
		$client_id = $this->_client->id;
		$client_secret = $this->_client->secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
//		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'grant_type'=>'authorization_code',
			'client_id'=>$this->_client->id,
			'client_secret'=>$this->_client->secret,
			'code'=>"false_code_".$this->_verifier->code,
			'redirect_uri'=>'https%3A%2F%2Fclient.example.com%2Fcb',
			);
		$sData = '';
		foreach($aData as $key=>$val){
			$sData.="&$key=$val";
		}

		$sData=substr($sData,1);
		
		curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
		curl_exec($rCurl);
		$info=curl_getinfo($rCurl);
		$this->assertTrue($info['http_code']==400, 'response status code should be 400');

    }

    public function testValidClientByHeader()
	{
		$client_id = $this->_client->id;
		$client_secret = $this->_client->secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'grant_type'=>'none',
			);
		$sData = '';
		foreach($aData as $key=>$val){
			$sData.="&$key=$val";
		}

		$sData=substr($sData,1);
		
		curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
		$ret = curl_exec($rCurl);
		$info=curl_getinfo($rCurl);
		$this->assertTrue($info['http_code']==200, 'response status code should be 200');

    }

    public function testValidClientByContent()
	{
		$client_id = $this->_client->id;
		$client_secret = $this->_client->secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
//		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'grant_type'=>'none',
			'client_id'=>$this->_client->id,
			'client_secret'=>$this->_client->secret,
			);
		$sData = '';
		foreach($aData as $key=>$val){
			$sData.="&$key=$val";
		}

		$sData=substr($sData,1);
		
		curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
		$ret = curl_exec($rCurl);
		$info=curl_getinfo($rCurl);
		$this->assertTrue($info['http_code']==200, 'response status code should be 200');

    }

	public function tearDown(){
		$this->_store->fini();
		$this->_store = null;
	}
}

