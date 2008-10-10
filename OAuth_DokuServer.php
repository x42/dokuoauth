<?php //vim: foldmethod=marker

class DokuOAuthServer extends OAuthServer {
/*
  public function get_dokuwiki_user_from_request($request) {
      // TODO: check parameter -> should be arrays..
      $this->get_dokuwiki_user($request['oauth_consumer_key'], $request['oauth_token']);
  } 
*/

  public function create_consumer($consumer_key=NULL, $consumer_secret=NULL, $callback_url=NULL) {
  	if (empty($consumer_key)) $consumer_key = $this->data_store->create_hash($user);
  	if (empty($consumer_secret)) $consumer_secret = $this->data_store->create_hash(sha1($user));
    	return $this->data_store->new_consumer($consumer_key, $consumer_secret, $callback_url);
  }

  # TODO:
  # - consumer may be limited to certain user or group
  # - request-tokens are generated and bound to logged on user (if available for this consumer-key)
  #   -> special consumers may 'auto-validate' to given user
  # - access-tokens are given/exchanged IFF the request-token is bound 
  #   -> delete prev mapping of request-token.
  #
  # - timeout delete nonce
  # - allow to set time-limit to tokens..

  public function map_dokuwiki_user($user, $consumer_key, $access_key=NULL) {
  	if (empty($user)) return FALSE; 
	# TODO - don't link user to consumer-key ... 
	# link user to accees_key !
    	$this->data_store->new_usermap($user, $consumer_key, $access_key);
	return TRUE;
  }

  public function get_dokuwiki_user($consumer, $token) {
    	return ($this->data_store->lookup_user($consumer->key, $token->key));
	#return 'rgareus';
  }

}

/*
class DokuOAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod_RSA_SHA1 {
  public function fetch_private_cert(&$request) {
    $cert = <<<EOD
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALRiMLAh9iimur8V
A7qVvdqxevEuUkW4K+2KdMXmnQbG9Aa7k7eBjK1S+0LYmVjPKlJGNXHDGuy5Fw/d
7rjVJ0BLB+ubPK8iA/Tw3hLQgXMRRGRXXCn8ikfuQfjUS1uZSatdLB81mydBETlJ
hI6GH4twrbDJCR2Bwy/XWXgqgGRzAgMBAAECgYBYWVtleUzavkbrPjy0T5FMou8H
X9u2AC2ry8vD/l7cqedtwMPp9k7TubgNFo+NGvKsl2ynyprOZR1xjQ7WgrgVB+mm
uScOM/5HVceFuGRDhYTCObE+y1kxRloNYXnx3ei1zbeYLPCHdhxRYW7T0qcynNmw
rn05/KO2RLjgQNalsQJBANeA3Q4Nugqy4QBUCEC09SqylT2K9FrrItqL2QKc9v0Z
zO2uwllCbg0dwpVuYPYXYvikNHHg+aCWF+VXsb9rpPsCQQDWR9TT4ORdzoj+Nccn
qkMsDmzt0EfNaAOwHOmVJ2RVBspPcxt5iN4HI7HNeG6U5YsFBb+/GZbgfBT3kpNG
WPTpAkBI+gFhjfJvRw38n3g/+UeAkwMI2TJQS4n8+hid0uus3/zOjDySH3XHCUno
cn1xOJAyZODBo47E+67R4jV1/gzbAkEAklJaspRPXP877NssM5nAZMU0/O/NGCZ+
3jPgDUno6WbJn5cqm8MqWhW1xGkImgRk+fkDBquiq4gPiT898jusgQJAd5Zrr6Q8
AO/0isr/3aa6O6NLQxISLKcPDk2NOccAfS/xOtfOz4sJYM3+Bs4Io9+dZGSDCA54
Lw03eHTNQghS0A==
-----END PRIVATE KEY-----
EOD;
    return $cert;
  }

  public function fetch_public_cert(&$request) {
    $cert = <<<EOD
-----BEGIN CERTIFICATE-----
MIIBpjCCAQ+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAZMRcwFQYDVQQDDA5UZXN0
IFByaW5jaXBhbDAeFw03MDAxMDEwODAwMDBaFw0zODEyMzEwODAwMDBaMBkxFzAV
BgNVBAMMDlRlc3QgUHJpbmNpcGFsMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC0YjCwIfYoprq/FQO6lb3asXrxLlJFuCvtinTF5p0GxvQGu5O3gYytUvtC2JlY
zypSRjVxwxrsuRcP3e641SdASwfrmzyvIgP08N4S0IFzEURkV1wp/IpH7kH41Etb
mUmrXSwfNZsnQRE5SYSOhh+LcK2wyQkdgcMv11l4KoBkcwIDAQABMA0GCSqGSIb3
DQEBBQUAA4GBAGZLPEuJ5SiJ2ryq+CmEGOXfvlTtEL2nuGtr9PewxkgnOjZpUy+d
4TvuXJbNQc8f4AMWL/tO9w0Fk80rWKp9ea8/df4qMq5qlFWlx6yOLQxumNOmECKb
WpkUQDIDJEoFUzKMVuJf4KO/FJ345+BNLGgbJ6WujreoM1X/gYfdnJ/J
-----END CERTIFICATE-----
EOD;
    return $cert;
  }
} 
*/

/**
 * A data store for testing
 */
class TestOAuthDataStore extends OAuthDataStore {/*{{{*/
    private $consumer;
    private $request_token;
    private $access_token;
    private $nonce;

    function __construct() {/*{{{*/
        $this->consumer = new OAuthConsumer("key", "secret", NULL);
        $this->request_token = new OAuthToken("requestkey", "requestsecret", 1);
        $this->access_token = new OAuthToken("accesskey", "accesssecret", 1);
        $this->nonce = "nonce";
    }/*}}}*/

    function lookup_consumer($consumer_key) {/*{{{*/
        if ($consumer_key == $this->consumer->key) return $this->consumer;
        return NULL;
    }/*}}}*/

    function lookup_token($consumer, $token_type, $token) {/*{{{*/
        $token_attrib = $token_type . "_token";
        if ($consumer->key == $this->consumer->key
            && $token == $this->$token_attrib->key) {
            return $this->$token_attrib;
        }
        return NULL;
    }/*}}}*/

    function lookup_nonce($consumer, $token, $nonce, $timestamp) {/*{{{*/
        if ($consumer->key == $this->consumer->key
            && (($token && $token->key == $this->request_token->key)
                || ($token && $token->key == $this->access_token->key))
            && $nonce == $this->nonce) {
            return $this->nonce;
        }
        return NULL;
    }/*}}}*/

    function new_request_token($consumer) {/*{{{*/
        if ($consumer->key == $this->consumer->key) {
            return $this->request_token;
        }
        return NULL;
    }/*}}}*/

    function new_access_token($token, $consumer) {/*{{{*/
        if ($consumer->key == $this->consumer->key
            && $token->key == $this->request_token->key) {
            return $this->access_token;
        }
        return NULL;
    }/*}}}*/
}/*}}}*/




/*  A very dbm-based oauth storage to come
 */
class DokuOAuthDataStore extends OAuthDataStore {/*{{{*/
    private $dbh;
    private $SALT='rg';

    function __construct($path = 'conf/oauth.gdbm') {/*{{{*/ /// XX DOKU_CONF 
        #print_r(dba_handlers());
	$this->dbh = dba_popen($path, 'c', 'inifile');

        if ($this->lookup_consumer("robin")== NULL) {
		// insert test consumer key & consumer secret
		$this->new_consumer("robin", "geheim");
		$this->new_usermap("rgareus", "robin");
		# in INI-format:
		#  consumer_robin=O:13:"OAuthConsumer":3:{s:3:"key";s:5:"robin";s:6:"secret";s:6:"geheim";s:12:"callback_url";N;}
		#  userC_robin=a:3:{s:4:"user";s:7:"rgareus";s:5:"token";s:5:"robin";s:6:"access";N;}
	}
    }/*}}}*/

    function __destruct() {/*{{{*/
	dba_close($this->dbh);
    }/*}}}*/

    function new_usermap($user, $consumer_key, $access_key = NULL) {/*{{{*/
	$data = array('user' => $user, 'consumer' => $consumer_key, 'access' => $access_key);
	# TODO; allow assign/revoke tokens ..
	if ($access_key!=NULL && 
	         !dba_insert("userA_$access_key", serialize($data), $this->dbh))
	    throw new OAuthException("doooom!");
	else if (!dba_insert("userC_$consumer_key", serialize($data), $this->dbh))
	    throw new OAuthException("doooom!");
    }/*}}}*/

    function lookup_user($consumer_key, $access_key = NULL) {/*{{{*/
        if ($access_key!=NULL) 
	    $rv = dba_fetch("userA_$access_key", $this->dbh);
	if ($rv === FALSE) { # for testing - map consumer to user :-X
	    $rv = dba_fetch("userC_$consumer_key", $this->dbh);
	}
	if ($rv === FALSE) return NULL;
	print_r($data);
	$data = unserialize($rv);
	if ($data['consumer'] != $consumer_key) return NULL;

	if (!empty($data['access'])  # TODO: require strict matching
	    && !empty($access_key) 
	    && $data['access'] != $access_key) return NULL;

	return $data['user'];
    }/*}}}*/

    function new_consumer($consumer_key, $consumer_secret, $callback_url=NULL) {/*{{{*/
	$consumer = new OAuthConsumer($consumer_key, $consumer_secret, $callback_url);
	if (!dba_insert("consumer_$consumer_key", serialize($consumer), $this->dbh)) {
	    throw new OAuthException("doooom!");
	}
	return $consumer;
    }/*}}}*/

    function lookup_consumer($consumer_key) {/*{{{*/
	$rv = dba_fetch("consumer_$consumer_key", $this->dbh);
	if ($rv === FALSE) {
	    return NULL;
	}
	$obj = unserialize($rv);
	if (!($obj instanceof OAuthConsumer)) {
	    return NULL;
	}
	return $obj;
    }/*}}}*/

    function lookup_token($consumer, $token_type, $token) {/*{{{*/
	$rv = dba_fetch("${token_type}_${token}", $this->dbh);
	if ($rv === FALSE) {
	    return NULL;
	}
	$obj = unserialize($rv);
	if (!($obj instanceof OAuthToken)) {
	    return NULL;
	}
	return $obj;
    }/*}}}*/

    function lookup_nonce($consumer, $token, $nonce, $timestamp) {/*{{{*/
	if (dba_exists("nonce_$nonce", $this->dbh)) {
	    return TRUE;
	} else {
	    # TODO: timestamp nonce 
	    # and clean up old-ones  -> oauth_timestamp ;; OAuthServer->timestamp_threshold (300 sec)
	    dba_insert("nonce_$nonce", "1", $this->dbh);
	    return FALSE;
	}
    }/*}}}*/

    function create_hash($pepper=NULL) {/*{{{*/
        if (empty($pepper)) $pepper=time();
	$rv = md5(time().$this->SALT.md5($pepper));
	return $rv;
    }/*}}}*/

    function new_token($consumer, $type="request") {/*{{{*/
	$key = $this->create_hash($consumer->key);
	$secret = time() + time();
	$token = new OAuthToken($key, md5(md5($secret)));
	if (!dba_insert("${type}_$key", serialize($token), $this->dbh)) {
	    throw new OAuthException("doooom!");
	}
	return $token;
    }/*}}}*/

    function new_request_token($consumer) {/*{{{*/
	return $this->new_token($consumer, "request");
    }/*}}}*/

    function new_access_token($token, $consumer) {/*{{{*/
	$token = $this->new_token($consumer, 'access');
	dba_delete("request_" . $token->key, $this->dbh);
	return $token;
    }/*}}}*/
}/*}}}*/

//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
