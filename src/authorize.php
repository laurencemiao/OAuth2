<?php


require_once 'HTTP/OAuth2/Exception.php';
require_once 'HTTP/OAuth2/Storage.php';
require_once 'HTTP/OAuth2/Server/Request.php';

require_once 'common.php';

$request=new HTTP_OAuth2_Server_Request();
$mystore=new My_Storage();

$params = $request->getQuery();

$user=new HTTP_OAuth2_Credential_User();
$user->username = __TEST_USERNAME__;


if(!empty($params['state'])) $state="&state=$params[state]";
else $state='';

if($params['type']=='web_server')
{
    $client=$mystore->selectClient($params['client_id']);
    $code=$mystore->createVerifier($client, $user);
    echo("Location: $params[redirect_uri]?code=$code$state");
}
elseif($params['type']=='user_agent')
{
    $client=$mystore->selectClient($params['client_id']);
    $token = $mystore->createAccessToken($client, $user);
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