<?php

require_once 'HTTP/OAuth2/Credential/Abstract.php';

class HTTP_OAuth2_Credential_User extends HTTP_OAuth2_Credential_Abstract{
    public $username = null;
    public $password = null;
}

