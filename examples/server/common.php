<?php

$__CUR_DIR__=dirname(__FILE__);
require_once "$__CUR_DIR__/../test_conf.php";

require_once 'HTTP/OAuth2/Server/Storage/Mock.php';
require_once 'HTTP/OAuth2/Server/EndPoint/Token.php';
require_once 'HTTP/OAuth2/Server/Request.php';
require_once 'HTTP/OAuth2/Server/EndPoint/Token.php';


$mystore=new HTTP_OAuth2_Server_Storage_Mock();

$mystore->init(__OAUTH2_TEST_TMP_DIR__);