<?php

require_once 'HTTP/OAuth2.php';
require_once 'HTTP/OAuth2/Client/Exception.php';

abstract class HTTP_OAuth2_Client extends HTTP_OAuth2{
    const CLIENT_TYPE_CONFIDENTIAL	= 'confidential';
    const CLIENT_TYPE_PUBLIC		= 'public';

    public $client_identifier		= null;
    public $type			= null;
    public $redirect_uri		= null;

    public $credentials			= null;
}
