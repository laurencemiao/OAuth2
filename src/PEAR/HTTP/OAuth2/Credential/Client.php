<?php

require_once 'HTTP/OAuth2/Credential/Core.php';

class HTTP_OAuth2_Credential_Client extends HTTP_OAuth2_Credential_Core{
    public $client_id = null;
    public $client_secret = null;
    private $_grant_types = '';
    
    function addGrantType($grant_type){
        if(false === strpos(",$this->_grant_types,",",$grant_type,")){
            if(empty($this->_grant_types)){
                $this->_grant_types = $grant_type;
            }else{
                $this->_grant_types .= ",$grant_type";
            }
        }
    }
    function deleteGrantType($grant_type){
        if(false !== strpos(",$this->_grant_types,",",$grant_type,")){
            $this->_grant_types = str_replace(",$grant_type",'',",$this->_grant_types");
            if(substr($this->_grant_types,0,1)==',') $this->_grant_types = substr($this->_grant_types,1);
        }
    }
    function checkGrantType($grant_type){
        if(false !== strpos(",$this->_grant_types,",",$grant_type,")){
            return 1;
        }else{
            return 0;
        }
    }

}

