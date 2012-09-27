<?php


class HTTP_OAuth2_Token_RefreshToken{

    /**
     * QUOTED FROM draft-ietf-oauth-v2-31,
     *
     * 3.2.1.  Client Authentication
     *
     *
     * o  Enforcing the binding of refresh tokens and authorization codes to
     * the client they were issued to.  Client authentication is critical
     * when an authorization code is transmitted to the redirection
     * endpoint over an insecure channel, or when the redirection URI has
     * not been registered in full.
     */
    public $client_id = null;
    public $redirect_uri = null;
    
    public $authorization_id = null;

}

