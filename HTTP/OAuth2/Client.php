<?php

require_once 'HTTP/OAuth2.php';
require_once 'HTTP/OAuth2/Client/Exception.php';

abstract class HTTP_OAuth2_Client extends HTTP_OAuth2{
    const CLIENT_TYPE_CONFIDENTIAL	= 'confidential';
    const CLIENT_TYPE_PUBLIC		= 'public';

    public $client_id			= null;
    public $type			= null;
    /**
     * QUOTED FROM draft-ietf-oauth-v2-31,
     *
     * 3.1.2.2. Registration Requirements
     *
     * The authorization server MUST require the following clients to
     * register their redirection endpoint:
     *
     * o  Public clients.
     * o  Confidential clients utilizing the implicit grant type.
     *
     * ...
     * The authorization server MAY allow the client to register multiple
     * redirection endpoints.
     */
    public $registered_redirect_uris	= array();

    /**
     * QUOTED FROM draft-ietf-oauth-v2-31,
     *
     * 3.1.2.3.  Dynamic Configuration
     *
     * If multiple redirection URIs have been registered, if only part of
     * the redirection URI has been registered, or if no redirection URI has
     * been registered, the client MUST include a redirection URI with the
     * authorization request using the "redirect_uri" request parameter.
     */
    public $redirect_uri		= null;
    public $credentials			= null;
}
