<?php

$__CUR_DIR__=dirname(__FILE__);
require_once "$__CUR_DIR__/common.php";
require_once 'HTTP/OAuth2/Server/EndPoint/Authorize.php';

$config = array(
    'grant_type' => array(
//        HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE => true,
//        HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC => true,
//        HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION => true,
//        HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE => true,
//        HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN => true,
        ),
    'access_token_expires_in' => 7200,
    'show_refresh_token' => true,
    );

$myserver=new HTTP_OAuth2_Server_EndPoint_Authorize($config, $mystore);

$username=null;
function myauthorize(){
	global $username;

	$username = __OAUTH2_TEST_USER_ID__;
	return 1;
}

function mygetuser(){
	global $username;

	return $username;
}

$myserver->authorize='myauthorize';
$myserver->getUser='mygetuser';

$myserver->handle();

