<?php

require_once 'HTTP/OAuth2/Server/Storage/Authorization.php';
require_once 'HTTP/OAuth2/Authorization/Client.php';
require_once 'HTTP/OAuth2/Authorization/Password.php';
require_once 'HTTP/OAuth2/Authorization/Code.php';
require_once 'HTTP/OAuth2/Token/AccessToken.php';
require_once 'HTTP/OAuth2/Token/RefreshToken.php';

abstract class HTTP_OAuth2_Server_Storage_Abstract
{

    // to avoid php complain about the protype dismatch while overriding,
    // defined as normal functions rather than abstract.
    function init(){}
    function fini(){}

    abstract function selectClient($client_id);
    abstract function createClient(HTTP_OAuth2_Authorization_Client $client);
    abstract function deleteClient($client_id);
    abstract function checkClient(HTTP_OAuth2_Authorization_Client $client);
    function existClient($client_id){
        $client = $this->selectClient($client_id);
        return empty($client) ? 0 : 1;
    }

    abstract function selectUser($username);
    abstract function createUser(HTTP_OAuth2_Authorization_Password $user);
    abstract function deleteUser($username);
    abstract function checkUser(HTTP_OAuth2_Authorization_Password $user);
    function existUser($username){
        $user = $this->selectUser($username);
        return empty($user) ? 0 : 1;
    }
    
    abstract function selectAuthorization($authorization_id);
    abstract function createAuthorization($type, $client_id, $key = null, $key_type = null, $scope = null);
    abstract function deleteAuthorization($authorization_id);
    abstract function checkAuthorization(HTTP_OAuth2_Token_Authorization $authen);
    function existAuthorization($authorization_id){
        $auth = $this->selectAuthorization($authorization_id);
        return empty($auth) ? 0 : 1;
    }

    abstract function selectAccessToken($access_token);
    abstract function createAccessToken(HTTP_OAuth2_Token_AccessToken $access_token);
    abstract function deleteAccessToken($access_token);
    abstract function checkAccessToken(HTTP_OAuth2_Token_AccessToken $access_token);
    function existAccessToken($access_token)
    {
        $token = $this->selectAccessToken($access_token);
        return empty($token) ? 0 : 1;
    }

    function selectAssertion($assertion_type, $assertion)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function createAssertion(HTTP_OAuth2_Authorization_Assertion $user)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function deleteAssertion($assertion_type, $assertion)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function checkAssertion(HTTP_OAuth2_Authorization_Assertion $user)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }

    function selectAuthorizationCode($code)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function createAuthorizationCode(HTTP_OAuth2_Token_AuthorizationCode $verifier)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function deleteAuthorizationCode($code)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function checkAuthorizationCode(HTTP_OAuth2_Token_AuthorizationCode $verifier)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function existAuthorizationCode($code)
    {
        $verifier = $this->selectAuthorizationCode($code);
        return empty($verifier) ? 0 : 1;
    }

    function selectRefreshToken($refresh_token)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function createRefreshToken(HTTP_OAuth2_Token_RefreshToken $refresh_token)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function deleteRefreshToken($refresh_token)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }
    function checkRefreshToken(HTTP_OAuth2_Token_RefreshToken $refresh_token)
    {
        throw new HTTP_OAuth2_Exception('Not Implemented!');
    }

}

