<?php //vim: foldmethod=marker

class DokuOAuthServer extends OAuthServer {
/*
  public function get_dokuwiki_user_from_request($request) {
      // TODO: check parameter -> should be arrays..
      $this->get_dokuwiki_user($request['oauth_consumer_key'], $request['oauth_token']);
  } 
*/
  public function get_dokuwiki_user($consumer, $token) {
	// TODO
	return 'rgareus';
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

    function __construct($path = 'conf/oauth.gdbm') {/*{{{*/ /// XX DOKU_CONF 
	$this->dbh = dba_popen($path, 'c', 'gdbm');
    }/*}}}*/

    function __destruct() {/*{{{*/
	dba_close($this->dbh);
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
	    dba_insert("nonce_$nonce", "1", $this->dbh);
	    return FALSE;
	}
    }/*}}}*/

    function new_token($consumer, $type="request") {/*{{{*/
	$key = md5(time());
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
