<?php

require_once 'HTTP/OAuth2.php';

class HTTP_OAuth2_Server_Response extends HTTP_OAuth2 implements ArrayAccess, Countable, IteratorAggregate {

    const STATUS_UNSUPPORTED_PARAMETER        = 0;
    const STATUS_UNSUPPORTED_SIGNATURE_METHOD = 1;
    const STATUS_MISSING_REQUIRED_PARAMETER   = 2;
    const STATUS_DUPLICATED_OAUTH_PARAMETER   = 3;

    const STATUS_INVALID_CONSUMER_KEY = 4;
    const STATUS_INVALID_TOKEN        = 5;
    const STATUS_INVALID_SIGNATURE    = 6;
    const STATUS_INVALID_NONCE        = 7;

    static protected $statusMap = array(
        self::STATUS_UNSUPPORTED_PARAMETER => array(
            400, 'Unsupported parameter'
        ),
        self::STATUS_UNSUPPORTED_SIGNATURE_METHOD => array(
            400, 'Unsupported signature method'
        ),
        self::STATUS_MISSING_REQUIRED_PARAMETER => array(
            400, 'Missing required parameter'
        ),
        self::STATUS_DUPLICATED_OAUTH_PARAMETER => array(
            400, 'Duplicated OAuth Protocol Parameter'
        ),
        self::STATUS_INVALID_CONSUMER_KEY => array(
            401, 'Invalid Consumer Key'
        ),
        self::STATUS_INVALID_TOKEN => array(
            401, 'Invalid / expired Token'
        ),
        self::STATUS_INVALID_SIGNATURE => array(
            401, 'Invalid signature'
        ),
        self::STATUS_INVALID_NONCE => array(
            401, 'Invalid / used nonce'
        )
    );

    /**
     * Headers to be sent the OAuth response
     *
     * @var array $headers Headers to send as an OAuth response
     */
    protected $headers = array();

    /**
     * Body of the response
     *
     * @var string $body Body of the response
     */
    protected $body = '';

    /**
     * Set realm
     *
     * @param string $realm Realm for the WWW-Authenticate header
     *
     * @return void
     */
    public function setRealm($realm)
    {
        $header = 'OAuth realm="' . $realm . '"';
        $this->setHeader('WWW-Authenticate', $header);
    }

    /**
     * Set header
     *
     * @param string $name  Name of the header
     * @param string $value Value of the header
     *
     * @return void
     */
    public function setHeader($name, $value)
    {
        $this->headers[$name] = $value;
    }

    /**
     * Get header
     *
     * @param string $name Name of header
     *
     * @return string|null Header if exists, null if not
     */
    public function getHeader($name)
    {
        if (array_key_exists($name, $this->headers)) {
            return $this->headers[$name];
        }

        return null;
    }

    /**
     * Get all headers
     *
     * @return array Current headers to send
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Set all headers
     *
     * @param array $headers Sets all headers to this name/value array
     *
     * @return void
     */
    public function setHeaders(array $headers)
    {
        $this->headers = $headers;
    }

    /**
     * Set status
     *
     * @param int $status Status constant
     *
     * @return void
     */
    public function setStatus($status)
    {
        if (!array_key_exists($status, self::$statusMap)) {
            throw new HTTP_OAuth_Exception('Invalid status');
        }

        list($code, $text) = self::$statusMap[$status];
        $this->setBody($text);

        if ($this->headersSent()) {
            throw new HTTP_OAuth_Exception('Status already sent');
        }

        switch ($code) {
        case 400:
            $this->header('HTTP/1.1 400 Bad Request');
            break;
        case 401:
            $this->header('HTTP/1.1 401 Unauthorized');
            break;
        }
    }

    /**
     * Headers sent
     *
     * @return bool If the headers have been sent
     */
    protected function headersSent()
    {
        return headers_sent();
    }

    /**
     * Header
     *
     * @param string $header Header to add
     *
     * @return void
     */
    protected function header($header)
    {
        return header($header);
    }

    /**
     * Prepare body
     *
     * Sets the body if nesscary
     *
     * @return void
     */
    protected function prepareBody()
    {
        if ($this->headersSent() && $this->getBody() !== '') {
            $this->err('Body already sent, not setting');
        } else {
            $this->setBody(json_encode($this->getParameters()));
        }
    }

    /**
     * Set body
     *
     * @param string $body Sets the body to send
     *
     * @return void
     */
    public function setBody($body)
    {
        $this->body = $body;
    }

    /**
     * Get body
     *
     * @return string Body that will be sent
     */
    public function getBody()
    {
        return $this->body;
    }

    /**
     * Send response
     *
     * Does a check whether or not headers have been sent in order
     * to determine if it can send them.
     *
     * @return void
     */
    public function send()
    {
        $this->prepareBody();
        if (!$this->headersSent()) {
            $this->header('HTTP/1.1 200 OK');
            foreach ($this->getHeaders() as $name => $value) {
                $this->header($name . ': ' . $value);
            }
        } else {
            $this->err('Headers already sent, can not send headers');
        }

        echo $this->getBody();
    }



    /**
     * OAuth Parameters
     *
     * @var string $oauthParams OAuth parameters
     */
    protected $oauthParams = array(
        'state',
        'immediate',
        'client_id',
        'client_secret',
        'code',
        'access_token',
        'refresh_token',
        'expires_in',
        'scope',
        'signature_method',
        'signature',
        'timestamp',
        'nonce',
        'version',
        'format',
        'redirect_uri',
        'error',
    );


    protected $parameters = array();

    protected $method = '';


    /**
     * Get parameters
     *
     * @return array Request's parameters
     */
    public function getParameters()
    {
        $params = $this->parameters;
        ksort($params);

        return $params;
    }

    /**
     * Set parameters
     *
     * @param array $params Name => value pair array of parameters
     *
     * @return void
     */
    public function setParameters(array $params)
    {
        foreach ($params as $name => $value) {
            $this->parameters[$name] = $value;
        }
    }

    /**
     * Get
     *
     * @param string $var Variable to get
     *
     * @return mixed Parameter if exists, else null
     */
    public function __get($var)
    {
        if (array_key_exists($var, $this->parameters)) {
            return $this->parameters[$var];
        }

        $method = 'get' . ucfirst($var);
        if (method_exists($this, $method)) {
            return $this->$method();
        }

        return null;
    }

    /**
     * Set
     *
     * @param string $var Name of the variable
     * @param mixed  $val Value of the variable
     *
     * @return void
     */
    public function __set($var, $val)
    {
        $this->parameters[$var] = $val;
    }

    /**
     * Offset exists
     *
     * @param string $offset Name of the offset
     *
     * @return bool Offset exists or not
     */
    public function offsetExists($offset)
    {
        return isset($this->parameters[$offset]);
    }

    /**
     * Offset get
     *
     * @param string $offset Name of the offset
     *
     * @return string Offset value
     */
    public function offsetGet($offset)
    {
        return $this->parameters[$offset];
    }

    /**
     * Offset set
     *
     * @param string $offset Name of the offset
     * @param string $value  Value of the offset
     *
     * @return void
     */
    public function offsetSet($offset, $value)
    {
        $this->parameters[$offset] = $value;
    }

    /**
     * Offset unset
     *
     * @param string $offset Name of the offset
     *
     * @return void
     */
    public function offsetUnset($offset)
    {
        unset($this->parameters[$offset]);
    }

    /**
     * Count
     *
     * @return int Amount of parameters
     */
    public function count()
    {
        return count($this->parameters);
    }

    /**
     * Get iterator
     *
     * @return ArrayIterator Iterator for self::$parameters
     */
    public function getIterator()
    {
        return new ArrayIterator($this->parameters);
    }

}


