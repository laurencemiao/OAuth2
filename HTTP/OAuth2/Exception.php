<?php

require_once 'PEAR/Exception.php';

class HTTP_OAuth2_Exception extends PEAR_Exception
{
    public function __construct($message = '', $p2 = null, $p3 = null)
    {
        parent::__construct($message, $p2, $p3);
    }
}

?>
