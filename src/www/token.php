<?php

require_once 'common.php';

require_once 'HTTP/OAuth2/Server/Storage/Mock.php';
require_once 'HTTP/OAuth2/Server/EndPoint/Token.php';

$config = array(
    'grant_type' => array(
        HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE => true,
        HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC => true,
        HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION => true,
        HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE => true,
        HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN => true,
        ),
    'access_token_expires_in' => 7200,
    'show_refresh_token' => true,
    );
    
$mystore=new HTTP_OAuth2_Server_Storage_Mock();
//$mystore->init(__OAUTH2_TEST_UNIX_TMP_DIR__);
$mystore->init(__OAUTH2_TEST_WIN_TMP_DIR__);

$myserver=new HTTP_OAuth2_Server_EndPoint_Token($config, $mystore);

$myserver->handle();

