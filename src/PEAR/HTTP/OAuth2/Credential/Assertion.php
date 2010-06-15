<?php

require_once 'HTTP/OAuth2/Credential/Core.php';

class HTTP_OAuth2_Credential_Assertion extends HTTP_OAuth2_Credential_Core{
    public $assertion_type = null;
    public $assertion = null;
}

