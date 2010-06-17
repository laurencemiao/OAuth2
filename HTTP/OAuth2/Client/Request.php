<?php

require_once 'HTTP/OAuth2/Client.php';
require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/Request2.php';

class HTTP_OAuth2_Client_Request extends HTTP_OAuth2_Client
{

    private $_request = null;
    private $_body = null;
    private $_client = null;
    private $_endpoint_url = null;
    private $_content_type = '';
    private $_method = '';
    private $_headers = array();
    private $_parameters=array();
    private $_auth_scheme = '';
    private $_auth_parameters = null;

    const HTTP_AUTHEN_SCHEME_BASIC = 'HTTP_BASIC';
    const HTTP_AUTHEN_SCHEME_DIGEST = 'HTTP_DIGEST';
    const HTTP_AUTHEN_SCHEME_TOKEN = 'HTTP_TOKEN';
    
    const HTTP_METHOD_GET       = 'GET';
    const HTTP_METHOD_POST      = 'POST';
    const HTTP_METHOD_DELETE    = 'DELETE';
    const HTTP_METHOD_HEAD      = 'HEAD';

	public function setClientCredential(HTTP_OAuth2_Credential_Client $client){
		$this->_client=$client;
	}
    
    public function setHeader($name, $value)
    {
        $this->_headers[$name] = $value;
    }

    public function setHeaders(array $headers)
    {
        $this->_headers = $headers;
    }

    public function setParameters(array $params)
    {
        foreach ($params as $name => $value) {
            $this->_parameters[$name] = $value;
        }
    }

    public function setUrl($url){
		$this->_endpoint_url=$url;
	}

	public function send(){
		$oRequest = new HTTP_Request2();

		$oRequest->setUrl($this->_endpoint_url);
		$oRequest->setMethod(HTTP_Request2::METHOD_POST);
		$oRequest->addPostParameter($this->_parameters);
		$oRequest->addPostParameter('client_id',$this->_client->id);
		$oRequest->addPostParameter('client_secret',$this->_client->secret);
		$oResponse = $oRequest->send();
		$this->_body=$oRequest->getBody();

		return $oResponse;
	}

	public function getBody(){
		return $this->_body;
	}

    function getHeaders()
    {
        return $this->_headers;
    }

    function getHeader($name)
    {
        return isset($this->_headers[$name]) ? $this->_headers[$name] : null;
    }
    
    function getAuthenScheme()
    {
        return $this->_auth_scheme;
    }
    
    function getAuthenParameter($name)
    {
        return isset($this->_auth_parameters[$name]) ? $this->_auth_parameters[$name] : null;
    }

    function getAuthenParameters()
    {
        return $this->_auth_parameters;
    }

    function getContentType(){
        return $this->_content_type;
    }
    
    function getParameters(){
        return $this->_parameters;
    }

    function getParameter($name){
        return isset($this->_parameters[$name]) ? $this->_parameters[$name] : null;
    }

    public function getMethod(){
        return $this->_method;
    }
}
