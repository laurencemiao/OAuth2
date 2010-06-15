<?php

require_once 'HTTP/OAuth2/Authorization.php';

class HTTP_OAuth2_Token_RefreshToken{
    public $client = null;
    public $user = null;
    public $authorization = null;
    public $redirect_uri = null;
}

