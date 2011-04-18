<?php

require_once 'HTTP/OAuth2/Server/Storage.php';
require_once 'HTTP/OAuth2/Server/Storage/Abstract.php';
require_once 'HTTP/OAuth2/Server/Storage/Authorization.php';


class HTTP_OAuth2_Server_Storage_Mock extends HTTP_OAuth2_Server_Storage_Abstract
{

    private $_dir;
    
    function init($dir = "/tmp"){
        $this->_dir = $dir;
        if(!is_dir($this->_dir))
            mkdir($this->_dir);
    }
    
    function fini(){
        $files = glob($this->_dir."/*");
        foreach($files as $file){
            unlink($file);
        }
        rmdir($this->_dir);
    }
    
    private function _load($id){
        $obj = null;
        $file = "$this->_dir/$id";
        if(is_file($file)){
            $data = file_get_contents($file);
        }else{
            $data = '';
        }
        if(!empty($data))$obj = unserialize($data);
        return $obj;
    }
    
    private function _save($id, $obj){
        $file = "$this->_dir/$id";
        $ret = file_put_contents($file,serialize($obj));
        clearstatcache();
        return $ret;
    }
    
    private function _delete($id){
        $file = "$this->_dir/$id";
        $ret = 0;
        if(is_file($file)){
            $ret = unlink($file);
            clearstatcache();

        }
        return $ret;
    }

    function checkAssertion(HTTP_OAuth2_Authorization_Assertion $user)
    {
        return 1;
    }
    
    function createAuthorization($type, $client_id, $key = null, $key_type = null, $scope = null){
        $auth=new HTTP_OAuth2_Server_Storage_Authorization();
        $auth->type = $type;
        $auth->id = $client_id;
        $auth->key = $key;
        $auth->key_type = $key_type;
        $auth->id = md5("$client_id-$key-$key_type");
        $this->_save($auth->id, $auth);
        
        return $auth;
    }
    function deleteAuthorization($auth_id){
        $this->_delete($auth_id);
    }
    function selectAuthorization($auth_id){
        $auth=$this->_load($auth_id);
        
        return $auth;
    }
    function checkAuthorization(HTTP_OAuth2_Token_Authorization $authen){
        $check_authen = $this->selectAuthorization($authen->id);
        return $check_authen == $authen;
    }

    function selectClient($client_id){
        $client = $this->_load($client_id);

        return $client;
    }
    function deleteClient($client_id){}
    function createClient(HTTP_OAuth2_Authorization_Client $client){
        $this->_save($client->id,$client);

        return $client;
    }
    function checkClient(HTTP_OAuth2_Authorization_Client $client){
        $ret = 0;
        $check_client = $this->_load($client->id);
        if(!empty($check_client)){
            if($check_client->secret == $client->secret){
                $ret = 1;
            }
        }

        return $ret;
    }
    
    function selectAuthorizationCode($code){
        $verifier = $this->_load($code);
        return $verifier;
    }
    function createAuthorizationCode(HTTP_OAuth2_Authorization_Code $verifier)
    {

        $code = substr(md5($verifier->client_id.$verifier->username.microtime(1)),0,8);
        $verifier->code = $code;

        $this->_save($code, $verifier);

        return $verifier;
    }
    function deleteAuthorizationCode($code){
        $this->_delete($code);
    }
    function checkAuthorizationCode(HTTP_OAuth2_Authorization_Code $verifier){
        $ret = 0;
        $check_verifier = $this->selectAuthorizationCode($verifier->code);
        if(!empty($check_verifier)){
            if($verifier->id == $check_verifier->id &&
                $verifier->redirect_uri == $check_verifier->redirect_uri){
                $ret = 1;
            }
        }
        
        return $ret;
    }

    function selectRefreshToken($refresh_token)
    {
        $token = $this->_load($refresh_token);
        return $token;
    }
    function createRefreshToken(HTTP_OAuth2_Token_RefreshToken $token){
        $authorization_id = $token->authorization_id;
        $token->token = md5($authorization_id.microtime(1));
        $this->_save($token->token, $token);
        
        return $token;
    }
    function deleteRefreshToken($refresh_token){}
    function checkRefreshToken(HTTP_OAuth2_Token_RefreshToken $refresh_token){}

    function checkUser(HTTP_OAuth2_Authorization_Password $user){
        $ret = 0;
        $check_user = $this->_load($user->username);
        if(!empty($check_user)){
            if($check_user->password == $user->password){
                $ret = 1;
            }
        }

        return $ret;
    }

    function selectAccessToken($access_token){
        $token = $this->_load($access_token);
        return $token;
    }
    function createAccessToken(HTTP_OAuth2_Token_AccessToken $token){
        $authorization_id = $token->authorization_id;
        $token->token = md5($authorization_id.microtime(1));
        $token->secret = md5($authorization_id.microtime(1).uniqid());
        $this->_save($token->token, $token);

        return $token;
    }
    function deleteAccessToken($access_token){}
    function checkAccessToken(HTTP_OAuth2_Token_AccessToken $access_token){}

    function selectUser($username){
        $user = $this->_load($username);
        return $user;
    }
    function createUser(HTTP_OAuth2_Authorization_Password $user){
        $this->_save($user->username, $user);

        return $user;
    }
    function deleteUser($username){}
}

