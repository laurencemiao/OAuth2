<?php

require_once 'HTTP/OAuth2/Server/EndPoint.php';
require_once 'HTTP/OAuth2/Server/Request.php';
require_once 'HTTP/OAuth2/Server/Response.php';
require_once 'HTTP/OAuth2/Credential/Client.php';
require_once 'HTTP/OAuth2/Credential/User.php';
require_once 'HTTP/OAuth2/Credential/Assertion.php';
require_once 'HTTP/OAuth2/Server/Storage/Abstract.php';



class HTTP_OAuth2_Server_EndPoint_Abstract extends HTTP_OAuth2_Server_EndPoint
{
    protected $_store;
    protected $_config;
    
    function __construct(array $config, HTTP_OAuth2_Server_Storage_Abstract $store=null){
        $this->_config = $config;
        $this->_store = $store;
    }
}