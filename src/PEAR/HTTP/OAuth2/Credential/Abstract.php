<?php
abstract class HTTP_OAuth2_Credential_Abstract{
    abstract static public function authenticate(HTTP_OAuth2_Credential_Abstract $object, HTTP_OAuth2_Credential_Abstract $check_object);
}

