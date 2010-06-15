<?php

require_once 'common.php';

require_once 'HTTP/OAuth2/Storage/Mock.php';
require_once 'HTTP/OAuth2/Server/Token.php';

$mystore=new HTTP_OAuth2_Storage_Mock();

$myserver=new HTTP_OAuth2_Server_Token($mystore);

$myserver->handle();

