<?php

require_once 'HTTP/OAuth2/Server.php';
require_once 'HTTP/OAuth2/Server/EndPoint/Exception.php';

abstract class HTTP_OAuth2_Server_EndPoint extends HTTP_OAuth2_Server{

    const ERROR_CODE_INCORRECT_CLIENTCREDENTIAL = "incorrect_client_credentials";

}


