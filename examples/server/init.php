<?php

$__CUR_DIR__=dirname(__FILE__);
require_once "$__CUR_DIR__/common.php";

$client=new HTTP_OAuth2_Authorization_Client();
$client->id = __OAUTH2_TEST_CLIENT_ID__;
$client->secret = __OAUTH2_TEST_CLIENT_SECRET__;

/*
$client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_AUTHORIZATIONCODE);
$client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_USERBASIC);
$client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_ASSERTION);
$client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_REFRESHTOKEN);
$client->addGrantType(HTTP_OAuth2::TOKEN_GRANT_TYPE_NONE);
*/

$user=new HTTP_OAuth2_Authorization_Password();
$user->username = __OAUTH2_TEST_USER_ID__;
$user->password = __OAUTH2_TEST_USER_SECRET__;

$mystore->createClient($client);
$mystore->createUser($user);

if($mystore->checkClient($client)){
    echo "client object created\n";
}else{
    echo "FAILED to create client object, make sure your temp dir is writable\n";
}

if($mystore->checkUser($user)){
    echo "user object created\n";
}else{
    echo "FAILED to create user object, make sure your temp dir is writable\n";
}

