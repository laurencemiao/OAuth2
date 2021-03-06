<?php

require_once 'HTTP/OAuth2/Server/EndPoint.php';
require_once 'HTTP/OAuth2/Request.php';
require_once 'HTTP/OAuth2/Response.php';
require_once 'HTTP/OAuth2/Authorization/Client.php';
require_once 'HTTP/OAuth2/Authorization/Password.php';
require_once 'HTTP/OAuth2/Authorization/Assertion.php';
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
