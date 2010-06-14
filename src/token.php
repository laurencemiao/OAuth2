<?php

require_once 'HTTP/OAuth2/Storage.php';
require_once 'HTTP/OAuth2/Server/Token.php';

require_once 'common.php';

$mystore=new My_Storage();

$myserver=new HTTP_OAuth2_Server_Token($mystore);

$myserver->handle();

