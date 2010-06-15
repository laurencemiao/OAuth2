<?php

require_once '../commen.php';
require_once 'HTTP/OAuth2/Storage/Mock.php';
require_once 'PHPUnit/Framework.php';
 
define('__OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__','storage_mock_');

class Storage_Mock extends PHPUnit_Framework_TestCase
{
	private $_store = null;
	public function setUp(){
		$this->_store = new HTTP_OAuth2_Storage_Mock();
	}

    public function testCreateClient()
    {
		$client = new HTTP_OAuth2_Credential_Client();

		$client->client_id = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.uniqid();
		$client->client_secret = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.md5(uniqid());

		$this->_store->createClient($client);
		$stored_client = $this->_store->selectClient($client->client_id);
        $this->assertTrue($client == $stored_client, 'stored client should equal to the original one');
 
        //$this->markTestIncomplete(
        //  'This test has not been implemented yet.'
        //);
    }

    public function testCreateUser()
    {
		$user = new HTTP_OAuth2_Credential_User();

		$user->username = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.uniqid();
		$user->password = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.md5(uniqid());

		$this->_store->createUser($user);
		$stored_user = $this->_store->selectUser($user->username);
        $this->assertTrue($user == $stored_user, 'stored user should equal to the original one');
    }

    public function testCreateVerifier()
    {
		$client = new HTTP_OAuth2_Credential_Client();

		$client->client_id = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.uniqid();
		$client->client_secret = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.md5(uniqid());

		$user = new HTTP_OAuth2_Credential_User();

		$user->username = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.uniqid();
		$user->password = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.md5(uniqid());

		$verifier = $this->_store->createVerifier($client, $user);
		$stored_verifier = $this->_store->selectVerifier($verifier->code);
        $this->assertTrue($verifier == $stored_verifier, 'stored verifier should equal to the original one');
    }

    public function testCreateAuthorization()
    {
		$client = new HTTP_OAuth2_Credential_Client();

		$client->client_id = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.uniqid();
		$client->client_secret = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.md5(uniqid());

		$user = new HTTP_OAuth2_Credential_User();

		$user->username = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.uniqid();
		$user->password = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.md5(uniqid());

		$auth = $this->_store->createAuthorization($client->client_id, $user->username);
		$stored_auth = $this->_store->selectAuthorization($client->client_id, $user->username);
        $this->assertTrue($auth == $stored_auth, 'stored authorization should equal to the original one');
    }

	public function tearDown(){
		$this->_store = null;
		$files = glob(__OAUTH2_TEST_TMP_DIR__."/".__OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__."*");
		foreach($files as $file){
			unlink($file);
		}
	}
}

