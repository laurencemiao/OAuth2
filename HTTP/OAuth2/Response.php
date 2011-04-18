<?php

require_once 'HTTP/OAuth2/Server.php';

class HTTP_OAuth2_Server_Response extends HTTP_OAuth2_Server{

    const HTTP_STATUS_HEADER_200    =   'HTTP/1.1 200 OK';
    const HTTP_STATUS_HEADER_401    =   'HTTP/1.1 401 Unauthorized';
    const HTTP_STATUS_HEADER_400    =   'HTTP/1.1 400 Bad Request';

    private $_headers = array();
    private $_status_header = self::HTTP_STATUS_HEADER_200;
    private $_parameters = array();
    private $_body = '';

    public function setHeader($name, $value)
    {
        $this->_headers[$name] = $value;
    }

    public function setHeaders(array $headers)
    {
        $this->_headers = $headers;
    }

    public function setStatus($status_header)
    {
        $this->_status_header = $status_header;
    }
    

    public function build()
    {
        if(headers_sent() && $this->_body !== '') {
            return 0;
        } else {
            if(!empty($this->_parameters))$this->_body = json_encode($this->_parameters);
            return 1;
        }
    }

    public function send()
    {
        if (!headers_sent()){
            header($this->_status_header);
            foreach ($this->_headers as $name => $value) {
                header($name . ': ' . $value);
            }
        }
        echo $this->_body;
    }

    public function setParameters(array $params)
    {
        foreach ($params as $name => $value) {
            $this->_parameters[$name] = $value;
        }
    }

}


