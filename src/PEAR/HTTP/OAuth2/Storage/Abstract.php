<?php

require_once 'HTTP/OAuth2/Authorization.php';
require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/OAuth2/Credential/User.php';
require_once 'HTTP/OAuth2/Token/AccessToken.php';
require_once 'HTTP/OAuth2/Token/RefreshToken.php';
require_once 'HTTP/OAuth2/Token/AuthorizationCode.php';

abstract class HTTP_OAuth2_Storage_Abstract{

	// to avoid php complain about the protype dismatch, do not define init as abstract,
	// so that we can redefine the agument list
	function init(){}
	abstract function fini();

	abstract function selectAuthorization($client_id, $username = null);
	abstract function createAuthorization($client_id, $username = null);
	abstract function deleteAuthorization($client_id, $username = null);

	abstract function selectVerifier($code);
	abstract function createVerifier(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
	abstract function deleteVerifier($code);

	abstract function selectRefreshToken($refresh_token);
	abstract function createRefreshToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
	abstract function deleteRefreshToken($refresh_token);

	abstract function selectAccessToken($access_token);
	abstract function createAccessToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
	abstract function deleteAccessToken($access_token);

    abstract function selectClient($client_id);
	abstract function createClient(HTTP_OAuth2_Credential_Client $client);
	abstract function deleteClient($client_id);

    abstract function selectUser($username);
	abstract function createUser(HTTP_OAuth2_Credential_User $user);
	abstract function deleteUser($username);
}

