<?php

require_once 'HTTP/OAuth2/Exception.php';

class HTTP_OAuth2_Client_Exception extends HTTP_OAuth2_Exception
{
    public function __construct($message = '', $p2 = null, $p3 = null)
    {
        parent::__construct($message, $p2, $p3);
    }
}

