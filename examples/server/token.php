<?php

$__CUR_DIR__=dirname(__FILE__);
require_once "$__CUR_DIR__/common.php";


$config = array(
    'grant_type' => array(
        HTTP_OAuth2::GRANT_TYPE_AUTHORIZATIONCODE => true,
        HTTP_OAuth2::GRANT_TYPE_IMPLICIT => true,
        HTTP_OAuth2::GRANT_TYPE_PASSWORD => true,
        HTTP_OAuth2::GRANT_TYPE_CLIENT => true,
        ),
    'access_token_expires_in' => 7200,
    'show_refresh_token' => true,
    );

$myserver=new HTTP_OAuth2_Server_EndPoint_Token($config, $mystore);

$myserver->handle();

