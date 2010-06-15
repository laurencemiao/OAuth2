<?php

require_once 'HTTP/OAuth2/Server/Communication.php';

function http_digest_parse($txt)
{
   // protect against missing data
   $needed_parts = array('nonce'=>1, 'nc'=>1, 'cnonce'=>1, 'qop'=>1, 'username'=>1, 'uri'=>1, 'response'=>1);
   $data = array();

   preg_match_all('@(\w+)=(?:(?:\'([^\']+)\'|"([^"]+)")|([^\s,]+))@', $txt, $matches, PREG_SET_ORDER);

   foreach ($matches as $m) {
       $data[$m[1]] = $m[2] ? $m[2] : ($m[3] ? $m[3] : $m[4]);
       unset($needed_parts[$m[1]]);
   }

   return $needed_parts ? false : $data;
}

class HTTP_OAuth2_Server_Communication_Request extends HTTP_OAuth2_Server_Communication
{

    private $_content_type = '';
    private $_method = '';
    private $_headers = array();
    private $_parameters=array();
    private $_auth_scheme = '';
    private $_auth_parameters = null;

    const HTTP_AUTHEN_SCHEME_BASIC = 'HTTP_BASIC';
    const HTTP_AUTHEN_SCHEME_DIGEST = 'HTTP_DIGEST';
    const HTTP_AUTHEN_SCHEME_TOKEN = 'HTTP_TOKEN';    
    

    function build()
    {
        if(empty($_SERVER['REQUEST_METHOD']))
        {
            $this->_method = 'HEAD';
        }
        else
        {
            $this->_method = $_SERVER['REQUEST_METHOD'];
        }
        
        if(isset($_SERVER['PHP_AUTH_USER'])){
            $this->_auth_scheme = self::HTTP_AUTHEN_SCHEME_BASIC;
            $this->_auth_parameters = array('username'=>$_SERVER['PHP_AUTH_USER'],'password'=>$_SERVER['PHP_AUTH_PW']);
        }elseif(isset($_SERVER['PHP_AUTH_DIGEST'])){
            $this->_auth_scheme = self::HTTP_AUTHEN_SCHEME_DIGEST;
            $this->_auth_parameters = http_digest_parse($_SERVER['PHP_AUTH_DIGEST']);
        }

        if($this->_method == 'POST')
        {
            $this->_content_type=empty($_SERVER['CONTENT_TYPE'])?'':$_SERVER['CONTENT_TYPE'];
            if($this->_content_type == 'application/json')
            {
                $this->_parameters = json_decode(file_get_contents('php://input'),1);
                if(false === $this->_parameters)
                    throw new HTTP_OAuth2_Exception("failed to decode json data");
            }
            elseif($this->_content_type == 'application/x-www-form-urlencoded')
            {
                $this->_parameters=$_POST;
            }
            else
            {
                throw new HTTP_OAuth2_Exception("content type '$this->_content_type' not supported");
            }
        }
        elseif($this->_method == 'GET')
        {
            $this->_parameters=$_GET;
        }
        else
        {
            throw new HTTP_OAuth2_Exception("'$this->_method' method not supported");
        }

        if (function_exists('apache_request_headers')) {
            $this->_headers = apache_request_headers();
        }else{
            $this->_headers = http_get_request_headers();
        }
    }

    function getHeaders()
    {
        return $this->_headers;
    }

    function getHeader($name)
    {
        return isset($this->_headers[$name])?$this->_headers[$name]:null;
    }
    
    function getAuthenScheme()
    {
        return $this->_auth_scheme;
    }
    
    function getAuthenParameter($name)
    {
        return isset($this->_auth_parameters[$name])?$this->_auth_parameters[$name]:null;
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
        return isset($this->_parameters[$name])?$this->_parameters[$name]:null;
    }

    public function getMethod(){
        return $this->_method;
    }
}
