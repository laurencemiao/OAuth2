<?php

$__CUR_DIR__ = dirname(__FILE__);
require_once "$__CUR_DIR__/../common.php";
require_once 'HTTP/OAuth2/Server/Storage/Mock.php';
require_once 'PHPUnit/Framework.php';
 
class Storage_Mock extends PHPUnit_Framework_TestCase
{
	private $_store = null;
	public function setUp(){
		$this->_store = new HTTP_OAuth2_Server_Storage_Mock();
		$this->_store->init(__OAUTH2_TEST_TEMP_DIR__);
	}

    public function testCreateClient()
    {
		$client = new HTTP_OAuth2_Credential_Client();

		$client->id = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.uniqid();
		$client->secret = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.md5(uniqid());

		$this->_store->createClient($client);
		$stored_client = $this->_store->selectClient($client->id);
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

    public function testCreateAuthorizationCode()
    {
		$client = new HTTP_OAuth2_Credential_Client();

		$client->id = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.uniqid();
		$client->secret = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.md5(uniqid());

		$user = new HTTP_OAuth2_Credential_User();

		$user->username = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.uniqid();
		$user->password = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.md5(uniqid());

		$verifier = new HTTP_OAuth2_Token_AuthorizationCode();
		$verifier->client_id = $client->id;
		$verifier->username = $user->username;
		$this->_store->createAuthorizationCode($verifier);
		$stored_verifier = $this->_store->selectAuthorizationCode($verifier->code);
        $this->assertTrue($verifier == $stored_verifier, 'stored verifier should equal to the original one');
    }

    public function testCreateAuthorization()
    {
		$client_id = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'client_'.uniqid();

		$username = __OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__.'user_'.uniqid();

		$auth = $this->_store->createAuthorization(HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,$client_id, $username);
		$stored_auth = $this->_store->selectAuthorization($auth->id);
        $this->assertTrue($auth == $stored_auth, 'stored authorization should equal to the original one');
    }

	public function tearDown(){
		$this->_store->fini();
		$this->_store = null;
	}
}

