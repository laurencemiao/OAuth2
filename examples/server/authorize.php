<?php

require_once 'common.php';

$request=new HTTP_OAuth2_Server_Request();

$request->build();
$params = $request->getParameters();

$username = __OAUTH2_TEST_USER_ID__;

$client_id = $request->getParameter('client_id');


if($request->getParameter('type')=='web_server')
{
    if(!empty($params['state'])) $state="&state=$params[state]";
    else $state='';

    // user granted
    $authorization = $mystore->createAuthorization(
        HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
        $client_id,
        $username);

    $verifier=new HTTP_OAuth2_Token_AuthorizationCode();
    $verifier->username = $username;
    $verifier->id = $client_id;
    $verifier->authorization_id = $authorization->id;
    $verifier->redirect_uri = $params['redirect_uri'];
    $verifier->scope = isset($params['scope'])?$params['scope']:null;
    
    $verifier = $mystore->createAuthorizationCode($verifier);
    
    header("Location: $params[redirect_uri]?code=$verifier->code$state");
}
elseif($request->getParameter('type')=='user_agent')
{
    if(!empty($params['state'])) $state="?state=$params[state]";
    else $state='';

    // user granted
    $authorization = $mystore->createAuthorization(
        HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
        $client_id,
        $username);

    $client=$mystore->selectClient($client_id);
    $access_token = new HTTP_OAuth2_Token_AccessToken();
    $access_token->authorization_id = $authorization->id;
    $token = $mystore->createAccessToken($access_token);
    
    header("Location: $params[redirect_uri]$state#access_token=".$token->token);
}
else
{
    throw new HTTP_OAuth2_Exception("type error");
}
?>