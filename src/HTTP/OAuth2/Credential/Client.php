<?php

require_once 'HTTP/OAuth2/Credential/Core.php';

class HTTP_OAuth2_Credential_Client extends HTTP_OAuth2_Credential_Core{
    public $client_id = null;
    public $client_secret = null;
    private $_flows = '';
    
    function addFlow($flow){
        if(false === strpos(",$this->_flows,",",$flow,")){
            if(empty($this->_flows)){
                $this->_flows = $flow;
            }else{
                $this->_flows .= ",$flow";
            }
        }
    }
    function deleteFlow($flow){
        if(false !== strpos(",$this->_flows,",",$flow,")){
            $this->_flows = str_replace(",$flow",'',",$this->_flows");
            if(substr($this->_flows,0,1)==',') $this->_flows = substr($this->_flows,1);
        }
    }
    function checkFlow($flow){
        if(false !== strpos(",$this->_flows,",",$flow,")){
            return 1;
        }else{
            return 0;
        }
    }

}

