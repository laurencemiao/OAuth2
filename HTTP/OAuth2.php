<?php
/**
 * HTTP_OAuth2
 *
 * Implementation of the OAuth specification v2 draft-07
 *
 * PHP version 5.2.0+
 *
 * LICENSE: This source file is subject to the New BSD license that is
 * available through the world-wide-web at the following URI:
 * http://www.opensource.org/licenses/bsd-license.php. If you did not receive
 * a copy of the New BSD License and are unable to obtain it through the web,
 * please send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category  HTTP
 * @package   HTTP_OAuth2
 * @author    Laurence Miao <laurence.miao@gmail.com>
 * @copyright 2010 Laurence Miao <laurence.miao@gmail.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php New BSD License
 * @link      http://pear.php.net/package/HTTP_OAuth2
 * @link      http://github.com/laurencemiao/OAuth2
 */

require_once 'HTTP/OAuth2/Exception.php';

abstract class HTTP_OAuth2{

    // draft 15, token endpoint grant type
    const GRANT_TYPE_CODE		= 'authorization_code';
    const GRANT_TYPE_IMPLICIT		= 'implicit';
    const GRANT_TYPE_PASSWORD		= 'password';
    const GRANT_TYPE_CLIENT		= 'client_credentials';
    const GRANT_TYPE_EXTENTION		= 'extention';
    const GRANT_TYPE_REFRESHTOKEN	= 'refresh_token';

    const CLIENT_PROFILE_WEB		= 'web';
    const CLIENT_PROFILE_USERAGENT	= 'user-agent-based';
    const CLIENT_PROFILE_NATIVE		= 'native';

    // draft 15, authorization endpoint response_type
    const RESPONSE_TYPE_CODE		= 'code';
    const RESPONSE_TYPE_TOKEN		= 'token';

}


