<?php

require_once 'HTTP/OAuth2/Credential/Core.php';

class HTTP_OAuth2_Credential_AccessToken extends HTTP_OAuth2_Credential_Core{

    public $token = null;
    public $duration = null;
    public $expire_in = null;


}

