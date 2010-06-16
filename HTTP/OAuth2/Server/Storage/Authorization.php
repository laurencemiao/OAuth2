<?php
class HTTP_OAuth2_Server_Storage_Authorization{
    const AUTHORIZATION_TYPE_USER = 'USER';
    const AUTHORIZATION_TYPE_ASSERTION = 'ASSERTION';
    const AUTHORIZATION_TYPE_NONE = 'NONE';

    public $type = null;
    public $id = null;
    public $client_id = null;
    public $key = null;
    public $key_type = null;
    public $scope = null;
}

