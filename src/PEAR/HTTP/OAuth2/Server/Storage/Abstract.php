<?php

require_once 'HTTP/OAuth2/Server/Storage/Authorization.php';
require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/OAuth2/Credential/User.php';
require_once 'HTTP/OAuth2/Token/AccessToken.php';
require_once 'HTTP/OAuth2/Token/RefreshToken.php';
require_once 'HTTP/OAuth2/Token/AuthorizationCode.php';

abstract class HTTP_OAuth2_Server_Storage_Abstract{

    // to avoid php complain about the protype dismatch, do not define init as abstract,
    // so that we can redefine the agument list
    function init(){}
    abstract function fini();

    abstract function selectAuthorizationCode($code);
    abstract function createAuthorizationCode(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
    abstract function deleteAuthorizationCode($code);
    abstract function checkAuthorizationCode(HTTP_OAuth2_Token_AuthorizationCode $verifier);

    abstract function selectRefreshToken($refresh_token);
    abstract function createRefreshToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
    abstract function deleteRefreshToken($refresh_token);
    abstract function checkRefreshToken(HTTP_OAuth2_Credential_RefreshToken $refresh_token);

    abstract function selectAccessToken($access_token);
    abstract function createAccessToken(HTTP_OAuth2_Credential_Client $client, HTTP_OAuth2_Credential_User $user);
    abstract function deleteAccessToken($access_token);
    abstract function checkAccessToken(HTTP_OAuth2_Credential_AccessToken $access_token);

    abstract function selectClient($client_id);
    abstract function createClient(HTTP_OAuth2_Credential_Client $client);
    abstract function deleteClient($client_id);
    abstract function checkClient(HTTP_OAuth2_Credential_Client $client);

    abstract function selectUser($username);
    abstract function createUser(HTTP_OAuth2_Credential_User $user);
    abstract function deleteUser($username);
    abstract function checkUser(HTTP_OAuth2_Credential_User $user);
    
    function selectAssertion($assertion_type, $assertion){}
    function createAssertion(HTTP_OAuth2_Credential_Assertion $user){}
    function deleteAssertion($assertion_type, $assertion){}
    function checkAssertion(HTTP_OAuth2_Credential_Assertion $user){}

    abstract function selectAuthorization($client_id, $key = null, $key_type = null);
    abstract function createAuthorization($client_id, $key = null, $key_type = null);
    abstract function deleteAuthorization($client_id, $key = null, $key_type = null);
    abstract function checkAuthorization(HTTP_OAuth2_Token_Authorization $authen);
    
    function authenticate(HTTP_OAuth2_Credential_Abstract $object){
        
        $class = get_class($object);
        switch($class){
            case 'HTTP_OAuth2_Credential_Client':
                $check_obj = $this->selectClient($object->client_id);
                break;
            case 'HTTP_OAuth2_Credential_User':
                $check_obj = $this->selectUser($object->username);
                break;
            case 'HTTP_OAuth2_Credential_Assertion':
                $check_obj = $this->selectAssertion($object->assertion_type,$object->assertion);
                break;
            default:
                throw new HTTP_OAuth2_Server_Storage_Exception("class '$class' not supported");
        }
        
        if(empty($check_obj)) return 0;
        
        return call_user_func("$class::authenticate",$object, $check_obj);
    }

}

