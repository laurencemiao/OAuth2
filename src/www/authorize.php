<?php

require_once 'common.php';

require_once 'HTTP/OAuth2/Server/Storage/Mock.php';
require_once 'HTTP/OAuth2/Server/EndPoint/Token.php';
require_once 'HTTP/OAuth2/Server/Request.php';

$request=new HTTP_OAuth2_Server_Request();

$mystore=new HTTP_OAuth2_Server_Storage_Mock();
$mystore->init(__OAUTH2_TEST_WIN_TMP_DIR__);

$request->build();
$params = $request->getParameters();

$user=new HTTP_OAuth2_Credential_User();
$user->username = 'username_111888';
$username = $user->username;

$client_id = $params['client_id'];

if(!empty($params['state'])) $state="&state=$params[state]";
else $state='';

if($params['type']=='web_server')
{
    // user granted
    $authorization = $mystore->createAuthorization(
        HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
        $client_id,
        $username);

    $verifier=new HTTP_OAuth2_Token_AuthorizationCode();
    $verifier->username = $username;
    $verifier->client_id = $client_id;
    $verifier->authorization_id = $authorization->id;
    $verifier->redirect_uri = $params['redirect_uri'];
    $verifier->scope = isset($params['scope'])?$params['scope']:null;
    
    $verifier = $mystore->createAuthorizationCode($verifier);
    
    
    echo("Location: $params[redirect_uri]?code=$verifier->code$state");
}
elseif($params['type']=='user_agent')
{
    // user granted
    $authorization = $mystore->createAuthorization(
        HTTP_OAuth2_Server_Storage_Authorization::AUTHORIZATION_TYPE_USER,
        $client_id,
        $username);

    $client=$mystore->selectClient($client_id);
    $access_token = new HTTP_OAuth2_Token_AccessToken();
    $access_token->authorization_id = $authorization->id;
    $access_token->expires_in = $expires_in;
    $token = $mystore->createAccessToken($client, $user, $authorization->id);
    
    echo("Location: $params[redirect_uri]#access_token=".$token->token."$state");
}
else
{
    throw new HTTP_OAuth2_Exception("type error");
}
?>
<html>
<body>
<form>

</form>
</body>
</html>