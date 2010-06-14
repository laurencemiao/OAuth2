<?php

require_once 'HTTP/OAuth2.php';
require_once 'HTTP/OAuth2/Exception.php';
require_once 'HTTP/OAuth2/Server/Request.php';
require_once 'HTTP/OAuth2/Server/Response.php';
require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/OAuth2/Credential/User.php';

class HTTP_OAuth2_Server_Token
{
    const ERROR_MSG_REDIRECT_URI_MISMATCH = "redirect_uri_mismatch";
    const ERROR_MSG_BAD_VERIFICATION_CODE = "bad_verification_code";
    const ERROR_MSG_INCORRECT_CLIENT_CREDENTIAL = "incorrect_client_credentials";
    const ERROR_MSG_UNAUTHORIZED_CLIENT = "unauthorized_client"; // The client is not permitted to use this authorization grant type.
    const ERROR_MSG_INVALID_ASSERTION = "invalid_assertion";
    const ERROR_MSG_UNKNOWN_FORMAT = "unknown_format";
    const ERROR_MSG_AUTHORIZATION_EXPIRED = "authorization_expired";
    

    protected $_store;
    
    function __construct(HTTP_OAuth2_Storage $store=null){
        $this->_store = $store;
    }
    
    function checkClient(HTTP_OAuth2_Credential_Client $client)
    {
        return $this->_store->checkClient($client->client_id, $client->client_secret);
    }
    
    function checkUser(HTTP_OAuth2_Credential_User $user)
    {
        return $this->_store->checkUser($user->username, $user->password);
    }
    
    function checkVerifier($client_id, $code)
    {
        $verifier = $this->_store->selectVerifier($code);
        $client = $verifier->client;
        
        return $client_id == $client->client_id;
    }
    
    function getVerifier($code)
    {
        $verifier = $this->_store->selectVerifier($code);
        
        return $verifier;
    }

    function checkAssertion($client_id, $assertion_type, $assertion)
    {
        return 1;
    }
    
    function checkRefreshToken($client_id, $refresh_token)
    {
    }
    
    private function _guessFlow(HTTP_OAuth2_Server_Request $request){
        $params = $request->getQuery();

        if(!empty($params['code']))
        {
            return HTTP_OAuth2::CLIENT_FLOW_WEBSERVER;
        }
        elseif(!empty($params['username']))
        {
            return HTTP_OAuth2::CLIENT_FLOW_USERCREDENTIAL;
        }
        elseif(!empty($params['assertion_type']))
        {
            return HTTP_OAuth2::CLIENT_FLOW_ASSERTION;
        }
        elseif(!empty($params['refresh_token']))
        {
            return HTTP_OAuth2::CLIENT_FLOW_REFRESHTOKEN;
        }
        elseif(!empty($params['client_id']))
        {
            return HTTP_OAuth2::CLIENT_FLOW_CLIENTCREDENTIAL;
        }
        else
        {
            throw new HTTP_OAuth2_Exception('unrecognized client flow');
        }
    }
    
    private function _verifyParameter($flow, HTTP_OAuth2_Server_Request $request){
        $params = $request->getQuery();

        switch($flow)
        {
            case HTTP_OAuth2::CLIENT_FLOW_WEBSERVER:
                if(empty($params['code']))
                {
                    throw new HTTP_OAuth2_Exception(self::ERROR_MSG_BAD_VERIFICATION_CODE);
                }
                if(empty($params['redirect_uri']))
                {
                    throw new HTTP_OAuth2_Exception("'redirect_uri' empty");
                }
                break;
            case HTTP_OAuth2::CLIENT_FLOW_USERCREDENTIAL:
                if(empty($params['username']) || empty($params['password']))
                {
                    throw new HTTP_OAuth2_Exception("invalid username/password");
                }
                break;
            case HTTP_OAuth2::CLIENT_FLOW_ASSERTION:
                if(empty($params['assertion_type']) || empty($params['assertion']))
                {
                    throw new HTTP_OAuth2_Exception(self::ERROR_MSG_INVALID_ASSERTION);
                }
                break;
            case HTTP_OAuth2::CLIENT_FLOW_REFRESHTOKEN:
                if(empty($params['refresh_token']))
                {
                    throw new HTTP_OAuth2_Exception("'refresh_token' empty");
                }
                break;
            case HTTP_OAuth2::CLIENT_FLOW_CLIENTCREDENTIAL:
                if(empty($params['client_id']) || empty($params['client_secret']))
                {
                    throw new HTTP_OAuth2_Exception("invalid client_id/client_secret");
                }
                break;
            default:
                throw new HTTP_OAuth2_Exception('should never come here');
                break;
        }

    }
    
    private function _extractClient(HTTP_OAuth2_Server_Request $request){
        $params = $request->getQuery();
        $client=null;
        if(!empty($params['client_id'])){
            $client=new HTTP_OAuth2_Credential_Client();
            $client->client_id=$params['client_id'];
            if(!empty($params['client_secret']))
                $client->client_secret=$params['client_secret'];
        }
        return $client;
    }
    
    private function _process($flow, $params){

        $user=null;

        $client=$this->_store->selectClient($params['client_id']);

        if(empty($client))
            throw new HTTP_OAuth2_Exception('invalid client');
        
        if(!$client->checkFlow($flow))
            throw new HTTP_OAuth2_Exception('client flow not allowed');

        if($flow == HTTP_OAuth2::CLIENT_FLOW_WEBSERVER)
        {
            if(!$this->checkVerifier($params['client_id'], $params['code']))
            {
                throw new HTTP_OAuth2_Exception(self::ERROR_MSG_BAD_VERIFICATION_CODE);
            }

            $verifier = $this->getVerifier($params['code']);
            $user = $verifier->user;
        }
        elseif($flow == HTTP_OAuth2::CLIENT_FLOW_USERCREDENTIAL)
        {
            $user = new HTTP_OAuth2_Credential_User();
            $user->username = $params['username'];
            $user->password = $params['password'];
            if(!$this->checkUser($user))
            {
                throw new HTTP_OAuth2_Exception("invalid username/password");
            }
        }
        elseif($flow == HTTP_OAuth2::CLIENT_FLOW_ASSERTION)
        {
            if(!$this->checkAssertion($params['assertion_type'], $params['coassertionde']))
            {
                throw new HTTP_OAuth2_Exception(self::ERROR_MSG_INVALID_ASSERTION);
            }
        }
        elseif($flow == HTTP_OAuth2::CLIENT_FLOW_REFRESHTOKEN)
        {
            throw new HTTP_OAuth2_Exception("to be implemented");
        }
        elseif($flow == HTTP_OAuth2::CLIENT_FLOW_CLIENTCREDENTIAL)
        {
            throw new HTTP_OAuth2_Exception("to be implemented");
        }
        else
        {
            throw new HTTP_OAuth2_Exception('params error');
        }

        $refresh_token=$this->_store->createRefreshToken($client, $user);
        $access_token=$this->_store->createAccessToken($client, $user);

        $ret = array('access_token'=>$access_token->token,'refresh_token'=>$refresh_token->token);
        $ret['expires_in'] = 3600;
        
        return $ret;

    }

    function handle()
    {

        $response=new HTTP_OAuth2_Server_Response();

        try{
            $request=new HTTP_OAuth2_Server_Request();
        
            // do not permit other method
            if($request->getMethod() != 'POST')
            {
                throw new HTTP_OAuth2_Exception('method not supported');
            }

            $flow = $this->_guessFlow($request);
            
            $this->_verifyParameter($flow, $request);

            $params = $request->getQuery();
            $client=$this->_extractClient($request);
            
            if(empty($client))
                throw new HTTP_OAuth2_Exception("client_id missing");
            if(empty($client->client_secret))
                throw new HTTP_OAuth2_Exception("client_secret missing");
            
            if(!$this->checkClient($client))
                throw new HTTP_OAuth2_Exception(self::ERROR_MSG_INCORRECT_CLIENT_CREDENTIAL);
                
            $ret = $this->_process($flow, $params);

            if($flow == HTTP_OAuth2::CLIENT_FLOW_WEBSERVER)
            {
                $response->setHeader("Location",$params['redirect_uri']."?access_token=".$ret['access_token']);
                $response->send();
            }
            else
            {
                $response->setHeader("Content-Type",'application/json');
                $response->setParameters($ret);
                $response->send();
            }

        }catch(PEAR_Exception $e){
            $ret = array('error' => $e->getMessage());
            $response->setHeader("Content-Type",'application/json');
            $response->setParameters($ret);
            $response->send();
        }
    }

}
