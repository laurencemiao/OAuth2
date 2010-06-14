<?php
/**
 * HTTP_OAuth2
 *
 * Implementation of the OAuth specification v2 draft-06
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
 * @link      http://github.com/jeffhodsdon/HTTP_OAuth2
 */

abstract class HTTP_OAuth2{

    const CLIENT_FLOW_WEBSERVER = 'web_server';
    const CLIENT_FLOW_USERAGENT = 'user_agent';
    const CLIENT_FLOW_USERCREDENTIAL = 'user_credentials';
    const CLIENT_FLOW_CLIENTCREDENTIAL = 'client_credentials';
    const CLIENT_FLOW_ASSERTION = 'assertion';
    const CLIENT_FLOW_REFRESHTOKEN = 'refresh_token';

    static public function urldecode($item)
    {
        if (is_array($item)) {
            return array_map(array('HTTP_OAuth2', 'urldecode'), $item);
        }

        return rawurldecode($item);
    }
}


