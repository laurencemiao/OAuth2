<?php

require_once 'HTTP/OAuth2/Authorization/Abstract.php';

class HTTP_OAuth2_Authorization_Assertion extends HTTP_OAuth2_Authorization_Abstract{
    public $assertion_type = null;
    public $assertion = null;
}

