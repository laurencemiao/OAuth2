<?php
define("__OAUTH2_PEAR_DIR__",dirname(__FILE__)."/../../PEAR/");
$pearRoot        = __OAUTH2_PEAR_DIR__;
$pearLibrary = $pearRoot . DIRECTORY_SEPARATOR . '';

$sPath = array($pearLibrary,get_include_path());
set_include_path(implode(PATH_SEPARATOR, $sPath));
