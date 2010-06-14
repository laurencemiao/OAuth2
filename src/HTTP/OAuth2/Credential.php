<?php
abstract class HTTP_OAuth2_Credential{
	static public function factory($sType){

        $sType = str_replace('-', '_', $sType);
        $class  = 'HTTP_OAuth2_Credential_' . $sType;
        $file   = str_replace('_', '/', $class) . '.php';

        include_once $file;

        if (class_exists($class) === false) {
            throw new InvalidArgumentException('No such signature class');
        }

        $instance = new $class;
        if (!$instance instanceof HTTP_OAuth2_Credential_Core) {
            throw new InvalidArgumentException(
                'Signature class does not extend HTTP_OAuth_Signature_Common'
            );
        }

	return $instance;
	}
}

var_dump(HTTP_OAuth2_Credential::factory('Client'));

