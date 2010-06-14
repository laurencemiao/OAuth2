<?php

require_once 'HTTP/OAuth2.php';

class HTTP_OAuth2_Server_Request extends HTTP_OAuth2
{

    protected $_sContentType='';
    protected $_aQuery=array();

    function __construct()
    {
        if($this->getMethod()=='POST')
	    {
            $this->_sContentType=empty($_SERVER['CONTENT_TYPE'])?'':$_SERVER['CONTENT_TYPE'];
	    if($this->getContentType()=='application/json'){
$this->_aQuery=json_decode(file_get_contents('php://input'),1);
}elseif($this->getContentType()=='application/x-www-form-urlencoded'){
$this->_aQuery=$_POST;
}
}elseif($this->getMethod()=='GET'){
$this->_aQuery=$_GET;
}
}
function getContentType(){
return $this->_sContentType;
}
function getQuery(){
return $this->_aQuery;
}

public function getMethod(){
if (empty($_SERVER['REQUEST_METHOD'])) {
return 'HEAD';
}

return $_SERVER['REQUEST_METHOD'];
}

}


