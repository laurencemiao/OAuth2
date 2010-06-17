<?php
$__CUR_DIR__ = dirname(__FILE__);
define("__OAUTH2_PEAR_DIR__","$__CUR_DIR__/../../");
$pearRoot        = __OAUTH2_PEAR_DIR__;
$pearLibrary = $pearRoot . DIRECTORY_SEPARATOR . '';

$sPath = array($pearLibrary,get_include_path());
set_include_path(implode(PATH_SEPARATOR, $sPath));

define('__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT_PREFIX__','token_endpoint_');
define('__OAUTH2_TEST_UNIT_TOKEN_ENDPOINT__','http://localhost:12961/oauth2/server/token.php');
define('__OAUTH2_TEST_UNIT_CALLBACK__','http://localhost:12961/oauth2/client/cb.php');
define('__OAUTH2_TEST_UNIT_STORAGE_MOCK_PREFIX__','storage_mock_');
define('__OAUTH2_TEST_TEMP_DIR__','/home/mf/tmp/oauth2');


