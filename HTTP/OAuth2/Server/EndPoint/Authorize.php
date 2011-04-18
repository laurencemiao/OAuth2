<?php

require_once 'HTTP/OAuth2/Server/EndPoint/Abstract.php';

class HTTP_OAuth2_Server_EndPoint_Authorize extends HTTP_OAuth2_Server_EndPoint_Abstract
{

    // draft 15, error
    const ERROR_INVALID_REQUEST = "invalid_request";
    const ERROR_UNAUTHORIZED_CLIENT = "unauthorized_client";
    const ERROR_ACCESS_DENIED = "access_denied";
    const ERROR_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";
    const ERROR_INVALID_SCOPE = "invalid_scope";
    
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


    private function _isResponseTypeAllowed($response_type){
        $ret = 0;
        
        if($response_type == self::RESPONSE_TYPE_CODE || $response_type == self::RESPONSE_TYPE_TOKEN){
            $ret = 1;
        }
        
        return $ret;
    }
            
    private function _getResponseType(HTTP_OAuth2_Request $request){

        $response_type = $request->getParameter('response_type');

        return $response_type;
    }
    
    private function _verifyParameter(HTTP_OAuth2_Request $request){
        $params = $request->getParameters();
                
        if(empty($params['response_type']))
        {
            throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_UNSUPPORTED_RESPONSE_TYPE);
        }
        if(empty($params['client_id']))
        {
            throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_UNAUTHORIZED_CLIENT);
        }
        if(empty($params['redirect_uri']))
        {
            throw new HTTP_OAuth2_Server_EndPoint_Exception("'redirect_uri' empty");
        }
    }
    
    private function _extractClient(HTTP_OAuth2_Request $request){
        $client = null;

        $client_id = $request->getParameter('client_id');
        $client_secret = $request->getParameter('client_secret');
        $client = new HTTP_OAuth2_Authorization_Client();
        $client->id = $client_id;
        $client->secret = $client_secret;

        return $client;
    }
    
    private function _extractUser($user_authen_type, HTTP_OAuth2_Request $request){
        $user = null;

        if($user_authen_type == self::CLIENT_AUTHEN_TYPE_HTTPBASIC){
            $http_authen_params = $request->getAuthenParameters();
            $user = new HTTP_OAuth2_Authorization_Password();
            $user->username = $http_authen_params['username'];
            $user->password = empty($http_authen_params['password'])?null:$http_authen_params['password'];
        }elseif($user_authen_type == self::CLIENT_AUTHEN_TYPE_FORM){
            $username = $request->getParameter('username');
            $password = $request->getParameter('password');
            $user = new HTTP_OAuth2_Authorization_Password();
            $user->username = $username;
            $user->password = $password;
        }

        return $user;
    }

    public $authorize;
    public $getUser;

    private function _process($response_type, $client, $request){

        $refresh_token = null;
        $authorization = null;
        $getUser = $this->getUser;
        $authorize = $this->authorize;
        $username = $getUser();
        $client_id = $client->id;
        if($response_type == HTTP_OAuth2::RESPONSE_TYPE_CODE)
        {
            if($authorize())
            {
                $authorization = $this->_store->createAuthorization(
                    HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
                    $client_id,
                    $username);

                $verifier=new HTTP_OAuth2_Authorization_Code();
                $verifier->username = $username;
                $verifier->id = $client_id;
                $verifier->authorization_id = $authorization->id;
                $redirect_uri = $request->getParameter('redirect_uri');
                $verifier->redirect_uri = $redirect_uri;
                $verifier->scope = $request->getParameter('scope');
                $state = $request->getParameter('state');
                if(!empty($state)){
                    $state = "&state=$state";
                }
    
                $verifier = $this->_store->createAuthorizationCode($verifier);
    
                header("Location: $redirect_uri?code=$verifier->code$state");
            }else{
            }
        }
        elseif($response_type == HTTP_OAuth2::RESPONSE_TYPE_TOKEN)
        {
                $authorization = $this->_store->createAuthorization(
                    HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
                    $client_id,
                    $username);

                $access_token = new HTTP_OAuth2_Token_AccessToken();
                $access_token->authorization_id = $authorization->id;
                $token = $this->_store->createAccessToken($access_token);
    
                $redirect_uri = $request->getParameter('redirect_uri');
                $state = $request->getParameter('state');
                if(!empty($state)){
                    $state = "&state=$state";
                }
                header("Location: $redirect_uri#access_token=".$token->token.$state);
        }
        else
        {
            throw new HTTP_OAuth2_Server_EndPoint_Exception('should never come here');
        }
        
        $expires_in = $this->_getConfig('access_token_expires_in');
        if(!empty($access_token)){
            $ret = array('access_token'=>$access_token->token);
            if(!empty($expires_in))$ret['expires_in'] = $expires_in;
        }else{
            $ret = array();
        }
        
        return $ret;

    }
    
    function handle()
    {

        try{
            $response=new HTTP_OAuth2_Response();

            $request=new HTTP_OAuth2_Request();
            if(!$request->build()){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_UNKNOWN_FORMAT);
            }
        
            // other method not allowd
            if(false === array_search($request->getMethod(),array(HTTP_OAuth2_Request::HTTP_METHOD_GET,HTTP_OAuth2_Request::HTTP_METHOD_POST)))
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception("method not '".$request->getMethod()."' allowed");
            }

            $this->_verifyParameter($request);

            $response_type = $this->_getResponseType($request);
            
	    if(!$this->_isResponseTypeAllowed($response_type))
	    {
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    "invalid response type '$response_type'");
            }
            
            $client = $this->_extractClient($request);

            $client = $this->_store->selectClient($client->id);
            if(empty($client))
                throw new HTTP_OAuth2_Server_EndPoint_Exception(
                    self::ERROR_UNAUTHORIZED_CLIENT);
            
            $ret = $this->_process($response_type, $client, $request);

            $response->setHeader("Content-Type",'application/json');
            $response->setParameters($ret);
            $response->build();
            $response->send();

        }catch(PEAR_Exception $e){
            $ret = array('error' => $e->getMessage());
            $response->setStatus(HTTP_OAuth2_Response::HTTP_STATUS_HEADER_400);
            $response->setHeader("Content-Type",'application/json');
            $response->setParameters($ret);
            $response->build();
            $response->send();
        }
    }
}
