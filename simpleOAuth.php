<?php
/* This class allows a simple creation of OAuth 1.0a requests. Usage requires
*  supplying all those fancy variables in the constructor, calling signRequest
*  if you want a signed request, then makeRequest.
*  @todo: implement OAuth 9.1.2 URL normalization */

class simpleOAuth {

	private $url;
	private $method;
	private $fields;

	public function __construct($url, $method, $fields) {
		if(preg_match('/\?/', $url)) $this->noSig = 'Absoluely not!'; // If there is any query string then signing will fail. That's fine, we can use this class as long as we don't attempt any signing, we'll be checking for this later, don't you even worry
		$this->url		= $url;
		$this->method	= strtoupper($method); // Of course everyone would fully capitalize the method they are trying to use, but just in case...
		if(!isset($fields['oauth_timestamp'])) $fields['oauth_timestamp'] = time(); // If no timestamp is supplied, then supply one. It's optional most of the time, but why not?
		if(isset($fields['oauth_version']) && $fields['oauth_version'] != '1.0') throw new Exception("This only supports oAuth version 1.0a, trick");
		elseif(!isset($fields['oauth_version'])) $fields['oauth_version'] = '1.0';
		$this->fields = $fields;
		if(!isset($fields['oauth_nonce'])) $this->fields['oauth_nonce'] = $this->generateNonce();
	}

	/* Function creates the three elements of the request, encodes them and concatenates them as per OAuth 1.0a section 9.1.3.
	*  Uses rawurlencode instead of the more common urlencode for RFC 3986 compliance. */
	private function buildSigBaseString() {
		$stringParts = array();
		$stringParts['method']	= rawurlencode($this->method);
		$stringParts['url']		= rawurlencode($this->url);
		$stringParts['request']	= rawurlencode($this->sortRenderFields());
		$string = implode('&', $stringParts);
		return $string;
	}

	/* This should give us pretty unique oauth nonce - build the basestring and attach the microtime, then MD5 it. */
	private function generateNonce() {
		$seed = $this->buildSigBaseString();
		$seed .= microtime(TRUE);
		$nonce = md5($seed);
		return $nonce;
	}
	
	private function sortRenderFields() {
		ksort($this->fields);
		$string = '';
		foreach($this->fields as $key => $val) {
			$string .= $key . '=' . $val . '&';
		}
		$string = substr($string, 0, -1);
		return $string;
	}

	public function signRequest($sigType = 'HMAC-SHA1', $consumer_secret, $token_secret='') {
		if(isset($this->noSig)) throw new Exception("Take your freaking query string out of the URL if you want to sign it. Come on.");
		$secret = $consumer_secret . '&' . $token_secret;

		$sigType = strtoupper($sigType); // Make sure this is uppercase, just for text matching purposes
		$this->fields['oauth_signature_method'] = $sigType;

		$baseString = $this->buildSigBaseString();

		if(strpos($sigType, 'HMAC-') === 0) {
			$sigTypeAlgo = substr($sigType, 5);
			$digest = hash_hmac($sigTypeAlgo, $baseString, $secret, TRUE);
			$this->fields['oauth_signature'] = rawurlencode(base64_encode($digest));
		}
		else throw new Exception('Sorry, I could not understand what method you want to sign this request with, Dave. I am planning to implement more methods soon, perhaps we will figure it out soon. If not, you are screwed.');
		// @todo make this work with other hashing methods
	}

	public function makeRequest() {
		if($this->method == 'POST') {
			// create a new cURL resource
			$ch = curl_init();
			ksort($this->fields);
			// set URL and other appropriate options
			curl_setopt($ch, CURLOPT_URL, $this->url);
			curl_setopt($ch, CURLOPT_HEADER, 0);
			curl_setopt($ch, CURLOPT_POST, TRUE);
			curl_setopt($ch, RETURNTRANSFER, TRUE);
			curl_setopt($ch, CURLOPT_POSTFIELDS, $this->fields);
			// grab URL and pass it to the browser
			$response = curl_exec($ch);
			// close cURL resource, and free up system resources
			curl_close($ch);
		} else {
			throw new Exception('None of those other fancy request types (you know, headers, GET, etc) have been created yet. Have a good night');
			// @todo figure out how to make this work with other request types
		}
		return $response;
	}

}
