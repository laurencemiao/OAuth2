<?php

require_once 'HTTP/OAuth2/Credential/Abstract.php';

class HTTP_OAuth2_Credential_Assertion extends HTTP_OAuth2_Credential_Abstract{
    public $assertion_type = null;
    public $assertion = null;
}

