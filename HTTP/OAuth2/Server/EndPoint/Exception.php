<?php

require_once 'HTTP/OAuth2/Server/Exception.php';

class HTTP_OAuth2_Server_EndPoint_Exception extends HTTP_OAuth2_Server_Exception
{
    public function __construct($message = '', $p2 = null, $p3 = null)
    {
        parent::__construct($message, $p2, $p3);
    }
}


