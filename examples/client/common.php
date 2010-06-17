<?php

$__CUR_DIR__=dirname(__FILE__);
require_once "$__CUR_DIR__/../test_conf.php";

$pearLibrary = $__CUR_DIR__ .'/../../'. DIRECTORY_SEPARATOR . '';
$sPath = array($pearLibrary,get_include_path());
set_include_path(implode(PATH_SEPARATOR, $sPath));

