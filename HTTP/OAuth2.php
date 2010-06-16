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

    // draft 08, client profiles
    const CLIENT_PROFILE_WEBSERVER = 'web_server';
    const CLIENT_PROFILE_USERAGENT = 'user_agent';
    const CLIENT_PROFILE_NATIVEAPPLICATION = 'native_application';
    const CLIENT_PROFILE_ASSERTION = 'autonomous';

    // draft 08, token endpoint grant type
    const TOKEN_GRANT_TYPE_AUTHORIZATIONCODE = 'authorization_code';
    const TOKEN_GRANT_TYPE_USERBASIC = 'user_basic_credentials';
    const TOKEN_GRANT_TYPE_ASSERTION = 'assertion';
    const TOKEN_GRANT_TYPE_NONE = 'none';
    const TOKEN_GRANT_TYPE_REFRESHTOKEN = 'refresh_token';

}

