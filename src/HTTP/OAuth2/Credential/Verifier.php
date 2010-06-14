<?php

require_once 'HTTP/OAuth2/Credential/Core.php';

class HTTP_OAuth2_Credential_Verifier extends HTTP_OAuth2_Credential_Core{
    public $client = null;
    public $user = null;
    public $code = null;
}

