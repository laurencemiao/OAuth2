<?php

require_once 'HTTP/OAuth2/Authorization/Abstract.php';

class HTTP_OAuth2_Authorization_Password extends HTTP_OAuth2_Authorization_Abstract{
    public $username = null;
    public $password = null;
}

