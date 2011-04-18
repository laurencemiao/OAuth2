<?php


define('__OAUTH2_TEST_CLIENT_ID__','client_id_xxx111');
define('__OAUTH2_TEST_CLIENT_SECRET__','client_secret_yyy222');
define('__OAUTH2_TEST_USER_ID__','username_aaa333');
define('__OAUTH2_TEST_USER_SECRET__','password_bbb444');

//define('__OAUTH2_TEST_TMP_DIR__','/tmp/oauth2');
define('__OAUTH2_TEST_TMP_DIR__','/home/woauth/tmp/oauth2');
//define('__OAUTH2_TEST_TMP_DIR__','c:\\temp\\oauth2');

$server_addr=$_SERVER['SERVER_ADDR'].":".$_SERVER['SERVER_PORT'];
$server_addr="192.168.0.101:12961";
define('__OAUTH2_TEST_REDIRECT_URI__',"http://$server_addr/oauth2/client/cb.php");
define('__OAUTH2_TEST_ENDPOINT_AUTHORIZE__',"http://$server_addr/oauth2/server/authorize.php");
define('__OAUTH2_TEST_ENDPOINT_TOKEN__',"http://$server_addr/oauth2/server/token.php");

