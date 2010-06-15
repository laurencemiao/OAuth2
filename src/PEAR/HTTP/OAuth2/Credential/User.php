<?php

require_once 'HTTP/OAuth2/Credential/Abstract.php';

class HTTP_OAuth2_Credential_User extends HTTP_OAuth2_Credential_Abstract{
    public $username = null;
    public $password = null;
    static public function authenticate(HTTP_OAuth2_Credential_Abstract $object, HTTP_OAuth2_Credential_Abstract $check_object){
        if($object->username == $check_object->username && $object->password == $check_object->password){
            return 1;
        }else{
            return 0;
        }
    }
}

