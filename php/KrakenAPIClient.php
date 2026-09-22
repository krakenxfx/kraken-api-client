<?php

namespace Payward;
/**
 * Reference implementation for Kraken's REST API.
 *
 * See https://www.kraken.com/help/api for more info.
 *
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Payward, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

class KrakenAPIException extends \ErrorException {};

class KrakenAPI
{
    protected $key;     // API key
    protected $secret;  // API secret
    protected $url;     // API base URL
    protected $version; // API version
    protected $curl;    // curl handle

    /**
     * Constructor for KrakenAPI
     *
     * @param string $key API key
     * @param string $secret API secret
     * @param string $url base URL for Kraken API
     * @param string $version API version
     * @param bool $sslverify whether TLS peer verification is enabled; false is rejected to fail closed
     */
    function __construct($key, $secret, $url='https://api.kraken.com', $version='0', $sslverify=true)
    {
        /* check we have curl */
        if(!function_exists('curl_init')) {
            print "[ERROR] The Kraken API client requires that PHP is compiled with 'curl' support.\n";
            exit(1);
        }

        $parsedUrl = parse_url($url);
        if(!is_array($parsedUrl) || !isset($parsedUrl['scheme']) || strtolower($parsedUrl['scheme']) !== 'https' || empty($parsedUrl['host'])) {
            throw new KrakenAPIException('API URL must be an absolute HTTPS URL.');
        }
        if(!$sslverify) {
            throw new KrakenAPIException('TLS certificate verification cannot be disabled.');
        }

        $this->key = $key;
        $this->secret = $secret;
        $this->url = $url;
        $this->version = $version;
        $this->curl = curl_init();

        curl_setopt_array($this->curl, array(
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_USERAGENT => 'Kraken PHP API Agent',
            CURLOPT_POST => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT => 30)
        );
    }

    function __destruct()
    {
        if(function_exists('curl_close') && !empty($this->curl)) {
            curl_close($this->curl);
        }
    }

    /**
     * Helper to retrieve JSON error message across legacy and modern PHP runtimes
     *
     * @return string
     */
    private function getJsonErrorMessage()
    {
        if(function_exists('json_last_error_msg')) {
            return json_last_error_msg();
        }

        switch (json_last_error()) {
            case JSON_ERROR_DEPTH:
                return 'Maximum stack depth exceeded';
            case JSON_ERROR_STATE_MISMATCH:
                return 'Underflow or the modes mismatch';
            case JSON_ERROR_CTRL_CHAR:
                return 'Unexpected control character found';
            case JSON_ERROR_SYNTAX:
                return 'Syntax error, malformed JSON';
            case JSON_ERROR_UTF8:
                return 'Malformed UTF-8 characters, possibly incorrectly encoded';
            default:
                return 'Unknown JSON error';
        }
    }

    /**
     * Query public methods
     *
     * @param string $method method name
     * @param array $request request parameters
     * @return array request result on success
     * @throws KrakenAPIException
     */
    function QueryPublic($method, array $request = array())
    {
        // build the POST data string
        $postdata = http_build_query($request, '', '&');

        // make request
        curl_setopt($this->curl, CURLOPT_URL, $this->url . '/' . $this->version . '/public/' . $method);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $postdata);
        curl_setopt($this->curl, CURLOPT_HTTPHEADER, array());
        $result = curl_exec($this->curl);
        if($result === false)
            throw new KrakenAPIException('CURL error: ' . curl_error($this->curl));
        $httpCode = curl_getinfo($this->curl, CURLINFO_HTTP_CODE);
        if($httpCode < 200 || $httpCode >= 300)
            throw new KrakenAPIException('HTTP error: ' . $httpCode);

        // decode results
        $result = json_decode($result, true);
        if(json_last_error() !== JSON_ERROR_NONE || !is_array($result))
            throw new KrakenAPIException('JSON decode error: ' . $this->getJsonErrorMessage());

        return $result;
    }

    /**
     * Query private methods
     *
     * @param string $method method path
     * @param array $request request parameters
     * @return array request result on success
     * @throws KrakenAPIException
     */
    function QueryPrivate($method, array $request = array())
    {
        if(!isset($request['nonce'])) {
            // generate a 64 bit nonce using a timestamp at microsecond resolution
            // string functions are used to avoid problems on 32 bit systems
            $nonce = explode(' ', microtime());
            $request['nonce'] = $nonce[1] . str_pad(substr($nonce[0], 2, 6), 6, '0');
        }

        // build the POST data string
        $postdata = http_build_query($request, '', '&');

        // set API key and sign the message
        $path = '/' . $this->version . '/private/' . $method;
        $sign = hash_hmac('sha512', $path . hash('sha256', $request['nonce'] . $postdata, true), base64_decode($this->secret), true);
        $headers = array(
            'API-Key: ' . $this->key,
            'API-Sign: ' . base64_encode($sign)
        );

        // make request
        curl_setopt($this->curl, CURLOPT_URL, $this->url . $path);
        curl_setopt($this->curl, CURLOPT_POSTFIELDS, $postdata);
        curl_setopt($this->curl, CURLOPT_HTTPHEADER, $headers);
        $result = curl_exec($this->curl);
        if($result === false)
            throw new KrakenAPIException('CURL error: ' . curl_error($this->curl));
        $httpCode = curl_getinfo($this->curl, CURLINFO_HTTP_CODE);
        if($httpCode < 200 || $httpCode >= 300)
            throw new KrakenAPIException('HTTP error: ' . $httpCode);

        // decode results
        $result = json_decode($result, true);
        if(json_last_error() !== JSON_ERROR_NONE || !is_array($result))
            throw new KrakenAPIException('JSON decode error: ' . $this->getJsonErrorMessage());

        return $result;
    }
}