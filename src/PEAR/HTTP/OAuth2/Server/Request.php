<?php

require_once 'HTTP/OAuth2.php';

class HTTP_OAuth2_Server_Request extends HTTP_OAuth2
{

    private $_content_type = '';
    private $_method = '';
    private $_headers = array();
    private $_parameters=array();

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
