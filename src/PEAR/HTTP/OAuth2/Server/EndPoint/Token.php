<?php

require_once 'HTTP/OAuth2/Server/EndPoint/Abstract.php';

class HTTP_OAuth2_Server_EndPoint_Token extends HTTP_OAuth2_Server_EndPoint_Abstract
{

    // draft 08, response error code
    const ERROR_CODE_REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
    const ERROR_CODE_BAD_AUTHORIZATIONCODE = "bad_authorization_code";
    const ERROR_CODE_INCORRECT_CLIENTCREDENTIAL = "incorrect_client_credentials";
    const ERROR_CODE_UNAUTHORIZED_CLIENT = "unauthorized_client"; // The client is not permitted to use this access grant type.
    const ERROR_CODE_INVALID_ASSERTION = "invalid_assertion";
    const ERROR_CODE_UNKNOWN_FORMAT = "unknown_format";
    const ERROR_CODE_AUTHORIZATION_EXPIRED = "authorization_expired";
    const ERROR_CODE_MULTIPLE_CREDENTIALS = "multiple_credentials";
    const ERROR_CODE_INVALID_USERCREDENTIAL = "invalid_user_credentials";
    
    const CLIENT_AUTHEN_TYPE_HTTPBASIC = 'HTTPBASIC';
    const CLIENT_AUTHEN_TYPE_FORM = 'FORM';
    const CLIENT_AUTHEN_TYPE_MULTIPLE = 'MULTIPLE';
    const CLIENT_AUTHEN_TYPE_NONE = 'NONE';

    const USER_AUTHEN_TYPE_HTTPBASIC = 'HTTPBASIC';
    const USER_AUTHEN_TYPE_HTTPDIGEST = 'HTTPDIGEST';
    const USER_AUTHEN_TYPE_FORM = 'FORM';
    const USER_AUTHEN_TYPE_MULTIPLE = 'MULTIPLE';
    const USER_AUTHEN_TYPE_NONE = 'NONE';
    
    public function obtainByAuthorizationCode($code, $redirect_uri){
    }
    public function obtainByOwnerCredentials($username, $password){
    }
    public function obtainByAssertion($assertion_type, $assertion){
    }
    public function obtainByRefreshToken($refresh_token){
    }
    
    private function _getConfig($name){
        $ret = null;
        if(isset($this->_config[$name])){
            $ret = $this->_config[$name];
        }
        
        return $ret;
    }

    private function _getConfigGrantType($grant_type){
        $ret = null;
        if(isset($this->_config['grant_type'])){
            if(is_array($this->_config['grant_type'])){
                if(isset($this->_config['grant_type'][$grant_type]))
                {
                    $ret = $this->_config['grant_type'][$grant_type];
                }
            }
        }
        
        return $ret;
    }

    private function _isGrantTypeAllowed($grant_type){
        $ret = 0;
        $allowed = $this->_getConfigGrantType($grant_type);
        
        if(!empty($allowed)){
            $ret = 1;
        }
        
        return $ret;
    }
            
    private function _guessRequestGrantType(HTTP_OAuth2_Server_Request $request){

        // we don't really have to guess, after draft 08
        $grant_type = $request->getParameter('grant_type');
        if(empty($grant_type)) $grant_type = HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE;

        return $grant_type;
    }
    
    private function _verifyParameter($grant_type, HTTP_OAuth2_Server_Request $request){
        $params = $request->getParameters();
        $auth = $request->getAuthenParameters();
        $http_auth_scheme = $request->getAuthenScheme();
                
        switch($grant_type)
        {
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE:
                if(empty($params['code']))
                {
                    throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_BAD_AUTHORIZATIONCODE);
                }
                if(empty($params['redirect_uri']))
                {
                    throw new HTTP_OAuth2_Server_EndPoint_Exception("'redirect_uri' empty");
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC:
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION:
                if(empty($params['assertion_type']) || empty($params['assertion']))
                {
                    throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_ASSERTION);
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN:
                if(empty($params['refresh_token']))
                {
                    throw new HTTP_OAuth2_Server_EndPoint_Exception("'refresh_token' empty");
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE:
                break;
            default:
                throw new HTTP_OAuth2_Server_EndPoint_Exception('should never come here');
                break;
        }

    }
    
    private function _guessClientAuthenType($grant_type, HTTP_OAuth2_Server_Request $request){
    
        $client_authen_type = '';
        
        $http_auth_scheme = $request->getAuthenScheme();
                
        switch($grant_type)
        {
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    $client_authen_type = self::CLIENT_AUTHEN_TYPE_NONE;
                }else{
                    $client_authen_type = self::CLIENT_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_AUTHEN_TYPE_FORM;
                }
                break;
            default:
        }
        
        return $client_authen_type;
    }
    
    private function _guessUserAuthenType($grant_type, HTTP_OAuth2_Server_Request $request){
    
        $user_authen_type = '';
        
        $http_auth_scheme = $request->getAuthenScheme();
                
        switch($grant_type)
        {
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE:
                $user_authen_type = self::USER_AUTHEN_TYPE_NONE;
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC:
                $username = $request->getParameter('username');
                if(empty($username)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $user_authen_type = self::USER_AUTHEN_TYPE_HTTPBASIC;
                    elseif($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_DIGEST)
                        $user_authen_type = self::USER_AUTHEN_TYPE_HTTPDIGEST;
                    else
                        $user_authen_type = self::USER_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $user_authen_type = self::USER_AUTHEN_TYPE_MULTIPLE;
                    elseif($http_auth_scheme == HTTP_OAuth2_Server_Request::HTTP_AUTHEN_SCHEME_DIGEST)
                        $user_authen_type = self::USER_AUTHEN_TYPE_MULTIPLE;
                    else
                        $user_authen_type = self::USER_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION:
                $user_authen_type = self::USER_AUTHEN_TYPE_NONE;
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN:
                $user_authen_type = self::USER_AUTHEN_TYPE_NONE;
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE:
                $user_authen_type = self::USER_AUTHEN_TYPE_NONE;
                break;
            default:
        }
        
        return $user_authen_type;
    }
    
    private function _extractClient($client_authen_type, HTTP_OAuth2_Server_Request $request){
        $client = null;

        if($client_authen_type == self::CLIENT_AUTHEN_TYPE_HTTPBASIC){
            $http_authen_params = $request->getAuthenParameters();
            $client = new HTTP_OAuth2_Credential_Client();
            $client->client_id = $http_authen_params['username'];
            $client->client_secret = empty($http_authen_params['password'])?null:$http_authen_params['password'];
        }elseif($client_authen_type == self::CLIENT_AUTHEN_TYPE_FORM){
            $client_id = $request->getParameter('client_id');
            $client_secret = $request->getParameter('client_secret');
            $client = new HTTP_OAuth2_Credential_Client();
            $client->client_id = $client_id;
            $client->client_secret = $client_secret;
        }

        return $client;
    }
    
    private function _extractUser($user_authen_type, HTTP_OAuth2_Server_Request $request){
        $user = null;

        if($user_authen_type == self::CLIENT_AUTHEN_TYPE_HTTPBASIC){
            $http_authen_params = $request->getAuthenParameters();
            $user = new HTTP_OAuth2_Credential_User();
            $user->username = $http_authen_params['username'];
            $user->password = empty($http_authen_params['password'])?null:$http_authen_params['password'];
        }elseif($user_authen_type == self::CLIENT_AUTHEN_TYPE_FORM){
            $username = $request->getParameter('username');
            $password = $request->getParameter('password');
            $user = new HTTP_OAuth2_Credential_User();
            $user->username = $username;
            $user->password = $password;
        }

        return $user;
    }

    private function _process($grant_type, $client, $user, $request){

        $client = $this->_store->selectClient($client->client_id);
        
        if(!$client->checkGrantType($grant_type))
            throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_UNAUTHORIZED_CLIENT);

        $refresh_token = null;
        $authorization = null;
        if($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE)
        {
            
            if(!$this->_store->existAuthorizationCode($request->getParameter('code')))
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_BAD_AUTHORIZATIONCODE);
            }
            $verifier = $this->_store->selectAuthorizationCode($request->getParameter('code'));

            $client_id = $verifier->client_id;
            if($client_id != $client->client_id){
                throw new HTTP_OAuth2_Server_EndPoint_Exception("'client_id' not equal");
            }
            if($verifier->redirect_uri != $request->getParameter('redirect_uri')){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_REDIRECT_URI_MISMATCH);
            }
            
            $authorization_id = $verifier->authorization_id;
            
            $this->_store->deleteAuthorizationCode($verifier->code);
            
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC)
        {
            if(!$this->_store->checkUser($user))
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_USERCREDENTIAL);
            }
            $username = $user->username;
            $client_id = $client->client_id;
            $authorization = $this->_store->createAuthorization(
                HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
                $client_id,
                $username);
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION)
        {
            $assertion = new HTTP_OAuth2_Credential_Assertion();
            $assertion->assertion_type = $request->getParameter('assertion_type');
            $assertion->assertion = $request->getParameter('assertion');
            if(!$this->_store->checkAssertion($assertion))
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_ASSERTION);
            }
            $client_id = $client->client_id;
            $authorization = $this->_store->createAuthorization(
                HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_ASSERTION,
                $client_id,
                $assertion->assertion,
                $assertion->assertion_type);
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN)
        {
            $refresh_token = $this->_store->selectRefreshToken($request->getParameter('refresh_token'));
            $authorization_id = $refresh_token->authorization_id;
            if(!$this->_store->existAuthorization($authorization_id)){
                throw new HTTP_OAuth2_Server_EndPoint_Exception('authorization not exists');
            }
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE)
        {
            $client_id = $client->client_id;
            $authorization = $this->_store->createAuthorization(
                HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_NONE,
                $client_id);
        }
        else
        {
            throw new HTTP_OAuth2_Server_EndPoint_Exception('should never come here');
        }

        
        if(!empty($authorization))$authorization_id = $authorization->id;
        if(is_null($refresh_token)){
            $refresh_token = new HTTP_OAuth2_Token_RefreshToken();
            $refresh_token->authorization_id = $authorization_id;
            $this->_store->createRefreshToken($refresh_token);
        }
        $expires_in = $this->_getConfig('access_token_expires_in');
        
        $access_token = new HTTP_OAuth2_Token_AccessToken();
        $access_token->authorization_id = $authorization_id;
        $access_token->expires_in = $expires_in;
        $this->_store->createAccessToken($access_token);

        $ret = array('access_token'=>$access_token->token,'refresh_token'=>$refresh_token->token);
        if(!empty($expires_in))$ret['expires_in'] = $expires_in;
        
        return $ret;

    }
    
    function handle()
    {

        try{
            $response=new HTTP_OAuth2_Server_Response();

            $request=new HTTP_OAuth2_Server_Request();
            if(!$request->build()){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_CODE_UNKNOWN_FORMAT);
            }
        
            // other method not allowd
            if($request->getMethod() !=
                HTTP_OAuth2_Server_Request::HTTP_METHOD_POST)
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception("method not '".$request->getMethod()."' allowed");
            }

            $grant_type = $this->_guessRequestGrantType($request);
            
            if(!$this->_isGrantTypeAllowed($grant_type)){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    "grant type '$grant_type' not allowed");
            }
            
            $client_authen_type = 
                $this->_guessClientAuthenType($grant_type, $request);
            
            if(self::CLIENT_AUTHEN_TYPE_MULTIPLE == $client_authen_type){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_CODE_MULTIPLE_CREDENTIALS);
            }elseif(self::CLIENT_AUTHEN_TYPE_NONE == $client_authen_type){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_CODE_INCORRECT_CLIENTCREDENTIAL);
            }
            
            $client = $this->_extractClient($client_authen_type, $request);

            if(empty($client))
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_CODE_INCORRECT_CLIENTCREDENTIAL);

            if(!$this->_store->checkClient($client))
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_CODE_INCORRECT_CLIENTCREDENTIAL);

            $user_authen_type = $this->_guessUserAuthenType($grant_type, $request);

            if(self::USER_AUTHEN_TYPE_MULTIPLE == $user_authen_type){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_CODE_MULTIPLE_CREDENTIALS);
            }else{
                if(self::USER_AUTHEN_TYPE_NONE == $user_authen_type){
                    if(HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC == $grant_type)
                        throw new HTTP_OAuth2_Server_EndPoint_Exception(
                            self::ERROR_CODE_INVALID_USERCREDENTIAL);
                }
            }
            
            $user = $this->_extractUser($user_authen_type, $request);
            
            if($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC){
                if(empty($user))
                    throw new HTTP_OAuth2_Server_EndPoint_Exception(
                        self::ERROR_CODE_INVALID_USERCREDENTIAL);

                if(!$this->_store->checkUser($user))
                    throw new HTTP_OAuth2_Server_EndPoint_Exception(
                        self::ERROR_CODE_INVALID_USERCREDENTIAL);
            }

            $this->_verifyParameter($grant_type, $request);
            
            
            $ret = $this->_process($grant_type, $client, $user, $request);

            if($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE)
            {
                $redirect_uri = $request->getParameter('redirect_uri');
                if(isset($ret['error'])){
                    $response->setStatus(HTTP_OAuth2_Server_Response::HTTP_STATUS_HEADER_400);
                    $response->setHeader("Location",$redirect_uri."?access_token=".$ret['access_token']."&refresh_token=".$ret['refresh_token']);
                    $response->setHeader("Content-Type",'application/json');
                    $response->build();
                    $response->send();
                }else{
                    $response->setHeader("Content-Type",'application/json');
                    $response->setHeader("Location",$redirect_uri."?access_token=".$ret['access_token']."&refresh_token=".$ret['refresh_token']);
                    $response->build();
                    $response->send();
                }
            }
            else
            {
                $response->setHeader("Content-Type",'application/json');
                $response->setParameters($ret);
                $response->build();
                $response->send();
            }

        }catch(PEAR_Exception $e){
            $ret = array('error' => $e->getMessage());
            $response->setStatus(HTTP_OAuth2_Server_Response::HTTP_STATUS_HEADER_400);
            $response->setHeader("Content-Type",'application/json');
            $response->setParameters($ret);
            $response->build();
            $response->send();
        }
    }
}
