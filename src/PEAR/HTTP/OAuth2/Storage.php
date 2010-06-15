<?php

require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/OAuth2/Credential/AccessToken.php';
require_once 'HTTP/OAuth2/Credential/RefreshToken.php';
require_once 'HTTP/OAuth2/Credential/User.php';
require_once 'HTTP/OAuth2/Credential/Verifier.php';

abstract class HTTP_OAuth2_Storage{
	abstract function selectClient($sKey);
	abstract function selectUser($sKey);
	abstract function checkClient($sKey,$sSecret);
	abstract function checkUser($sKey,$sSecret);
	abstract function selectVerifier($sKey);
	abstract function createVerifier(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
	abstract function createRefreshToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
	abstract function createAccessToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
	abstract function createClient(HTTP_OAuth2_Credential_Client $client);
	abstract function createUser(HTTP_OAuth2_Credential_User $user);
}

