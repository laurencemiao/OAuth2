<?php

require_once 'HTTP/OAuth2/Server/EndPoint.php';
require_once 'HTTP/OAuth2/Server/Communication/Request.php';
require_once 'HTTP/OAuth2/Server/Communication/Response.php';
require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/OAuth2/Credential/User.php';

class HTTP_OAuth2_Server_EndPoint_Token extends HTTP_OAuth2_Server_EndPoint
{

    // draft 08, response error code
    const ERROR_CODE_REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
    const ERROR_CODE_BAD_AUTHORIZATIONCODE = "bad_authorization_code";
    const ERROR_CODE_INCORRECT_CLIENT_CREDENTIAL = "incorrect_client_credentials";
    const ERROR_CODE_UNAUTHORIZED_CLIENT = "unauthorized_client"; // The client is not permitted to use this access grant type.
    const ERROR_CODE_INVALID_ASSERTION = "invalid_assertion";
    const ERROR_CODE_UNKNOWN_FORMAT = "unknown_format";
    const ERROR_CODE_AUTHORIZATION_EXPIRED = "authorization_expired";
    const ERROR_CODE_MULTIPLE_CREDENTIALS = "multiple_credentials";
    const ERROR_CODE_INVALID_USERCREDENTIAL = "invalid_user_credentials";
    
    const CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC = 'HTTPBASIC';
    const CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM = 'FORM';
    const CLIENT_CREDENTIAL_AUTHEN_TYPE_MULTIPLE = 'MULTIPLE';
    const CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE = 'NONE';

    const USER_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC = 'HTTPBASIC';
    const USER_CREDENTIAL_AUTHEN_TYPE_HTTPDIGEST = 'HTTPDIGEST';
    const USER_CREDENTIAL_AUTHEN_TYPE_FORM = 'FORM';
    const USER_CREDENTIAL_AUTHEN_TYPE_MULTIPLE = 'MULTIPLE';
    const USER_CREDENTIAL_AUTHEN_TYPE_NONE = 'NONE';
    
    protected $_store;
    
    function __construct(HTTP_OAuth2_Server_Storage_Abstract $store=null){
        $this->_store = $store;
    }
    
    function checkVerifier($client_id, $code)
    {
        $verifier = $this->_store->selectVerifier($code);
		if(!empty($verifier)){
	        $client = $verifier->client;
        	return $client_id == $client->client_id;
		}else{
        	return 0;
		}
        
    }
    
    function checkAssertion($client_id, $assertion_type, $assertion)
    {
        return 1;
    }
    
    function checkRefreshToken($client_id, $refresh_token)
    {
    }
        
    private function _guessGrantType(HTTP_OAuth2_Server_Communication_Request $request){

		// we don't really have to guess, after draft 08
        $grant_type = $request->getParameter('grant_type');
        if(empty($grant_type)) $grant_type = HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE;

        return $grant_type;
    }
    
    private function _verifyParameter($grant_type, HTTP_OAuth2_Server_Communication_Request $request){
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
    
    private function _guessClientAuthenType($grant_type, HTTP_OAuth2_Server_Communication_Request $request){
    
        $client_authen_type = '';
        
        $http_auth_scheme = $request->getAuthenScheme();
                
        switch($grant_type)
        {
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE;
                }else{
                    $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE:
                $client_id = $request->getParameter('client_id');
                if(empty($client_id)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_MULTIPLE;
                    else
                        $client_authen_type = self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM;
                }
                break;
            default:
        }
        
        return $client_authen_type;
    }
    
    private function _guessUserAuthenType($grant_type, HTTP_OAuth2_Server_Communication_Request $request){
    
        $user_authen_type = '';
        
        $http_auth_scheme = $request->getAuthenScheme();
                
        switch($grant_type)
        {
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE:
                $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_NONE;
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC:
                $username = $request->getParameter('username');
                if(empty($username)){
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC;
                    elseif($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_DIGEST)
                        $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_HTTPDIGEST;
                    else
                        $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_NONE;
                }else{
                    if($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_BASIC)
                        $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_MULTIPLE;
                    elseif($http_auth_scheme == HTTP_OAuth2_Server_Communication_Request::HTTP_AUTHEN_SCHEME_DIGEST)
                        $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_MULTIPLE;
                    else
                        $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_FORM;
                }
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION:
                $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_NONE;
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN:
                $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_NONE;
                break;
            case HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE:
                $user_authen_type = self::USER_CREDENTIAL_AUTHEN_TYPE_NONE;
                break;
            default:
        }
        
        return $user_authen_type;
    }
    
    private function _extractClient($client_authen_type, HTTP_OAuth2_Server_Communication_Request $request){
        $client = null;

        if($client_authen_type == self::CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC){
            $http_authen_params = $request->getAuthenParameters();
            $client = new HTTP_OAuth2_Credential_Client();
            $client->client_id = $http_authen_params['username'];
            $client->client_secret = empty($http_authen_params['password'])?null:$http_authen_params['password'];
        }elseif($client_authen_type == self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM){
            $client_id = $request->getParameter('client_id');
            $client_secret = $request->getParameter('client_secret');
            $client = new HTTP_OAuth2_Credential_Client();
            $client->client_id = $client_id;
            $client->client_secret = $client_secret;
        }

        return $client;
    }
    
    private function _extractUser($user_authen_type, HTTP_OAuth2_Server_Communication_Request $request){
        $user = null;

        if($user_authen_type == self::CLIENT_CREDENTIAL_AUTHEN_TYPE_HTTPBASIC){
            $http_authen_params = $request->getAuthenParameters();
            $user = new HTTP_OAuth2_Credential_User();
            $user->username = $http_authen_params['username'];
            $user->password = empty($http_authen_params['password'])?null:$http_authen_params['password'];
        }elseif($user_authen_type == self::CLIENT_CREDENTIAL_AUTHEN_TYPE_FORM){
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
        if($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE)
        {
            $verifier = new HTTP_OAuth2_Token_AuthorizationCode();
            $verifier->code = $request->getParameter('code');
            
            if(!$this->_store->checkAuthorizationCode($verifier))
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_BAD_AUTHORIZATIONCODE);
            }

            $verifier = $this->_store->selectAuthorizationCode($request->getParameter('code'));
            $user = $verifier->user;
            $this->_store->createAuthorization($client->client_id,$user->username);
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC)
        {
            $this->_store->createAuthorization($client->client_id,$user->username);
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION)
        {
            if(!$this->checkAssertion($request->getParameter('assertion_type'), $request->getParameter('coassertionde')))
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_ASSERTION);
            }
//			$this->_store->createAuthorization($client->client_id);
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN)
        {
            $refresh_token = $this->_store->selectRefreshToken($request->getParameter('refresh_token'));
            if($refresh_token){
                $this->_store->createAuthorization($client->client_id);
            }
        }
        elseif($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE)
        {
            $this->_store->createAuthorization($client->client_id);
        }
        else
        {
            throw new HTTP_OAuth2_Server_EndPoint_Exception('params error');
        }

        if(is_null($refresh_token))$refresh_token=$this->_store->createRefreshToken($client, $user);
        $access_token=$this->_store->createAccessToken($client, $user);

        $ret = array('access_token'=>$access_token->token,'refresh_token'=>$refresh_token->token);
        $ret['expires_in'] = 3600;
        
        return $ret;

    }

    function handle()
    {

        try{
            $response=new HTTP_OAuth2_Server_Response();

            $request=new HTTP_OAuth2_Server_Communication_Request();
            $request->build();
        
            // do not permit other method
            if($request->getMethod() != 'POST')
            {
                throw new HTTP_OAuth2_Server_EndPoint_Exception('method not allowed');
            }

            $grant_type = $this->_guessGrantType($request);
            
            $client_authen_type = $this->_guessClientAuthenType($grant_type, $request);
            
            if(self::CLIENT_CREDENTIAL_AUTHEN_TYPE_MULTIPLE == $client_authen_type){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_MULTIPLE_CREDENTIALS);
            }elseif(self::CLIENT_CREDENTIAL_AUTHEN_TYPE_NONE == $client_authen_type){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INCORRECT_CLIENT_CREDENTIAL);
            }
            
            $client = $this->_extractClient($client_authen_type, $request);

            if(empty($client))
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INCORRECT_CLIENT_CREDENTIAL);

            if(!$this->_store->authenticate($client))
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INCORRECT_CLIENT_CREDENTIAL);

            $user_authen_type = $this->_guessUserAuthenType($grant_type, $request);

            if(self::USER_CREDENTIAL_AUTHEN_TYPE_MULTIPLE == $user_authen_type){
                throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_MULTIPLE_CREDENTIALS);
            }else{
                if(self::USER_CREDENTIAL_AUTHEN_TYPE_NONE == $user_authen_type){
                    if(HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC == $grant_type)
                        throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_USERCREDENTIAL);
                }
            }
            
            $user = $this->_extractUser($user_authen_type, $request);
            
            if($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC){
                if(empty($user))
                    throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_USERCREDENTIAL);

                if(!$this->_store->authenticate($user))
                    throw new HTTP_OAuth2_Server_EndPoint_Exception(self::ERROR_CODE_INVALID_USERCREDENTIAL);
            }

            $this->_verifyParameter($grant_type, $request);

            $ret = $this->_process($grant_type, $client, $user, $request);

            if($grant_type == HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE)
            {
                $redirect_uri = $request->getParameter('redirect_uri');
                if(isset($ret['error'])){
                    $response->setStatus(HTTP_OAuth2_Server_Response::STATUS_MISSING_REQUIRED_PARAMETER);
                    $response->setHeader("Location",$redirect_uri."?access_token=".$ret['access_token']);
                    $response->setHeader("Content-Type",'application/json');
                    $response->send();
                }else{
                    $response->setHeader("Content-Type",'application/json');
                    $response->setHeader("Location",$redirect_uri."?access_token=".$ret['access_token']);
                    $response->send();
                }
            }
            else
            {
                $response->setHeader("Content-Type",'application/json');
                $response->setParameters($ret);
                $response->send();
            }

        }catch(PEAR_Exception $e){
            $ret = array('error' => $e->getMessage());
            $response->setStatus(HTTP_OAuth2_Server_Response::STATUS_MISSING_REQUIRED_PARAMETER);
            $response->setHeader("Content-Type",'application/json');
            $response->setParameters($ret);
            $response->send();
        }
    }
}
