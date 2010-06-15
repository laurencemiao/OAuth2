<?php

require_once '../commen.php';
require_once 'HTTP/OAuth2/Storage/Mock.php';
require_once 'PHPUnit/Framework.php';
 
define('__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__','token_endpoin_');
define('__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__','http://172.16.1.34:12961/oauth2/token.php');

class Token_EndPoint extends PHPUnit_Framework_TestCase
{
	private $_store = null;
	private $_client = null;
	private $_user = null;
	private $_verifier = null;
	private $_verifier1 = null;

	public function setUp(){
		$this->_store = new HTTP_OAuth2_Storage_Mock();
		$this->_client = new HTTP_OAuth2_Credential_Client();

		$this->_client->client_id = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'client_'.uniqid();
		$this->_client->client_secret = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'client_'.md5(uniqid());

		$this->_store->createClient($this->_client);

		$this->_user = new HTTP_OAuth2_Credential_User();

		$this->_user->username = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'user_'.uniqid();
		$this->_user->password = __OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__.'user_'.md5(uniqid());

		$this->_store->createUser($this->_user);

		$this->_verifier = $this->_store->createVerifier($this->_client, $this->_user);
		$this->_verifier1 = $this->_store->createVerifier($this->_client, $this->_user);
	}

    public function testVerificationValidCode()
    {
		$client_id = $this->_client->client_id;
		$client_secret = $this->_client->client_secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
//		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'client_id'=>$this->_client->client_id,
			'client_secret'=>$this->_client->client_secret,
			'code'=>$this->_verifier->code,
			'redirect_uri'=>'https%3A%2F%2Fclient.example.com%2Fcb',
			);
		$sData = '';
		foreach($aData as $key=>$val){
			$sData.="&$key=$val";
		}

		$sData=substr($sData,1);
		
		curl_setopt($rCurl,CURLOPT_POSTFIELDS,$sData);
		$ret = curl_exec($rCurl);
		echo $ret;
		$info=curl_getinfo($rCurl);
		$this->assertTrue($info['http_code']==302, 'response status code should be 302');

    }

    public function testVerificationInvalidCode()
	{
		$client_id = $this->_client->client_id;
		$client_secret = $this->_client->client_secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
//		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'client_id'=>$this->_client->client_id,
			'client_secret'=>$this->_client->client_secret,
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
		$client_id = $this->_client->client_id;
		$client_secret = $this->_client->client_secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array();
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
		$client_id = $this->_client->client_id;
		$client_secret = $this->_client->client_secret;
		$rCurl=curl_init();
		curl_setopt($rCurl,CURLOPT_URL,__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__);
		curl_setopt($rCurl,CURLOPT_VERBOSE,0);
		curl_setopt($rCurl,CURLOPT_MUTE,1);
		curl_setopt($rCurl,CURLOPT_RETURNTRANSFER,1);
		curl_setopt($rCurl,CURLOPT_POST,1);
		curl_setopt($rCurl,CURLOPT_HEADER,1);
//		curl_setopt($rCurl,CURLOPT_HTTPHEADER,array('Authorization: Basic '.base64_encode("$client_id:$client_secret")));
		$aData=array(
			'client_id'=>$this->_client->client_id,
			'client_secret'=>$this->_client->client_secret,
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
		$this->_store = null;
		$files = glob(__OAUTH2_TEST_TMP_DIR__."/".__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__."*");
		foreach($files as $file){
			unlink($file);
		}
	}
}

