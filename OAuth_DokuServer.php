<?php 

class DokuOAuthServer extends OAuthServer {/*{{{*/

    public function create_consumer($consumer_key=NULL, $consumer_secret=NULL, $callback_url=NULL) {/*{{{*/
        if (empty($consumer_key)) $consumer_key = $this->data_store->create_hash($user);
        if (empty($consumer_secret)) $consumer_secret = $this->data_store->create_hash(sha1($user));
        return $this->data_store->new_consumer($consumer_key, $consumer_secret, $callback_url);
    }/*}}}*/

    public function map_consumer($consumer_key, $acllimit) {/*{{{*/
        if (empty($consumer_key)) return FALSE; 
        if (!is_array($acllimit)) return FALSE; 
        $this->data_store->new_usermap($acllimit, 'userC', $consumer_key);
        return TRUE;
    }/*}}}*/

    public function map_user($user, $consumer_key, $token) {/*{{{*/
        if (empty($user) || is_array($user)) return FALSE; 
        if (empty($consumer_key)) return FALSE; 
        if (empty($token)) return FALSE; 
        $this->data_store->new_usermap($user, 'userT', $consumer_key, $token);
        return TRUE;
    }/*}}}*/

    public function unmap_user($token) {/*{{{*/
        if (empty($token)) return FALSE; 
        // TODO lookup, check if exists?! -> return FALSE.
        $this->data_store->del_usermap('userT', $token);
        $this->data_store->del_usermap('userX', $token);
        $this->data_store->del_usermap('request', $token);
        $this->data_store->del_usermap('access', $token);
        return TRUE;
    }/*}}}*/

    public function delete_consumer($consumer_key) {/*{{{*/
        $this->data_store->del_consumer($consumer_key);
        $this->data_store->del_usermap('userC', $consumer_key);
        return TRUE;
    }/*}}}*/

    public function list_consumers() {/*{{{*/
        return ($this->data_store->all_consumers());
    }/*}}}*/

    public function list_usertokens($username) {/*{{{*/
        return ($this->data_store->list_tokens($username));
    }/*}}}*/

    public function get_consumer_acl($consumer_key) {/*{{{*/
        return ($this->data_store->lookup_consumeracl($consumer_key));
    }/*}}}*/

    public function get_token_by_key($consumer_key, $token_key) {/*{{{*/
        if  (NULL !=($rv=$this->data_store->lookup_token($consumer_key, 'access', $token_key))) {
            return (array('type'=>'access', 'obj' => $rv));
        }
        if  (NULL != ($rv=$this->data_store->lookup_token($consumer_key, 'request', $token_key))) {
            return (array('type'=>'request', 'obj' => $rv));
        }
        return (NULL);
    }/*}}}*/

    public function get_consumer_by_key($consumer_key) {/*{{{*/
        return ($this->data_store->lookup_consumer($consumer_key));
    }/*}}}*/

    // TODO: delete consumer.. and settings

    public function map_requesttoken($consumer_key, $token) {/*{{{*/
        $this->data_store->new_usermap($consumer_key, 'userX', '!CONSUMER-KEY!', $token);
    }/*}}}*/

    public function get_consumer_by_requesttoken($token) {/*{{{*/
        return ($this->data_store->lookup_consumermap($token));
    }/*}}}*/

    public function get_dokuwiki_user($consumer_key, $token_key) {/*{{{*/
        $user=$this->data_store->lookup_user($consumer_key, $token_key);
        return ($user);
    }/*}}}*/

    public function get_consumer_settings($consumer_key) {/*{{{*/
        return $this->data_store->get_consettings($consumer_key);
    }/*}}}*/

    public function set_consumer_settings($consumer_key,$cs) {/*{{{*/
        $data=$this->data_store->set_consettings($consumer_key,$cs);
        return TRUE;
    }/*}}}*/

    public function load_session($onetimepass) {/*{{{*/
        $data=$this->data_store->get_session($onetimepass);
        if (!is_array($data)) return NULL;
        if (empty($data['created'])) return NULL;
        $now = time();
        if ($now - $data['created'] > $this->timestamp_threshold) {
            throw new OAuthException("Expired session.");
        }
        $sesdat=unserialize(rawurldecode($data['sesdat']));
        return $sesdat;
    }/*}}}*/

    public function save_session($sesdat) {/*{{{*/
        $pass=md5(time().$this->SALT.md5(time()*microtime()));
        $data = array('sesdat' => rawurlencode(serialize($sesdat)), 'created' => time());
        $this->data_store->new_session($pass, $data);
        return $pass;
    }/*}}}*/

}/*}}}*/


class DokuOAuthDataStore extends OAuthDataStore {/*{{{*/
    private $dbh;
    private $SALT='rg';

    function __construct($path = 'conf/oauth.gdbm') {/*{{{*/ /// XX DOKU_CONF 
        $this->dbh = dba_popen($path, 'c', 'inifile');
    }/*}}}*/

    function __destruct() {/*{{{*/
        dba_close($this->dbh);
    }/*}}}*/

    function new_usermap($userdata, $type='userC', $consumer_key, $token = NULL) {/*{{{*/
        $data = array('user' => $userdata, 'consumer' => $consumer_key, 'token' => $token, 'created' => time());
        if (empty($token)) $token=$consumer_key;
        // TODO: check if already exist?!
        if (!dba_insert("${type}_$token", serialize($data), $this->dbh))
            throw new OAuthException("doooom!");
    }/*}}}*/

    function del_usermap($type='userT', $token) {/*{{{*/
        dba_delete("${type}_$token", $this->dbh);
    }/*}}}*/

    function del_consumer($consumer_key) {/*{{{*/
        dba_delete("consumer_$consumer_key", $this->dbh);
        dba_delete("settings_$consumer_key", $this->dbh);
    }/*}}}*/

    function set_consettings($key, $data) {/*{{{*/
        dba_delete("settings_$key", $this->dbh);
        if (!dba_insert("settings_$key", serialize($data), $this->dbh))
            throw new OAuthException("doooom!");
    }/*}}}*/

    function get_consettings($key) {/*{{{*/
        $rv = dba_fetch("settings_$key", $this->dbh);
        if ($rv === FALSE) return NULL;
        return unserialize($rv);
    }/*}}}*/

    function new_session($pass, $data) {/*{{{*/
        if (!dba_insert("session_$pass", serialize($data), $this->dbh))
            throw new OAuthException("doooom!");
    }/*}}}*/

    function get_session($pass) {/*{{{*/
        $rv = dba_fetch("session_$pass", $this->dbh);
        if ($rv === FALSE) return NULL;
        dba_delete("session_".$pass, $this->dbh);
        return unserialize($rv);
    }/*}}}*/

    function lookup_consumeracl($consumer_key) {/*{{{*/
        $rv = dba_fetch("userC_$consumer_key", $this->dbh);
        if ($rv === FALSE) return NULL;
        $data = unserialize($rv);
        if ($data['consumer'] != $consumer_key) return NULL;
        return $data['user'];
    }/*}}}*/

    function lookup_user($consumer_key, $token) {/*{{{*/
        $rv = dba_fetch("userT_$token", $this->dbh);
        if ($rv === FALSE) return NULL;
        $data = unserialize($rv);
        if ($data['consumer'] != $consumer_key) return NULL;
        if ($data['token'] != $token) return NULL;
        return $data['user'];
    }/*}}}*/

    function lookup_consumermap($token) {/*{{{*/
        $rv = dba_fetch("userX_$token", $this->dbh);
        if ($rv === FALSE) return NULL;
        $data = unserialize($rv);
        if ($data['consumer'] != '!CONSUMER-KEY!') return NULL;
        if ($data['token'] != $token) return NULL;
        return $data['user'];
    }/*}}}*/

    function new_consumer($consumer_key, $consumer_secret, $callback_url=NULL) {/*{{{*/
        $consumer = new OAuthConsumer($consumer_key, $consumer_secret, $callback_url);
        if (!dba_insert("consumer_$consumer_key", serialize($consumer), $this->dbh)) {
            throw new OAuthException("doooom!");
        }
        return $consumer;
    }/*}}}*/

    function all_consumers() {/*{{{*/
        $key=dba_firstkey($this->dbh);
        $found=array();
        $consumers=array();
        while ($key != false) {
            if (!strncmp($key,"consumer_",9) )
                $found[] = $key;
            $key = dba_nextkey($this->dbh);
        }
        foreach ($found as $consumer) {
            $rv = dba_fetch($consumer, $this->dbh);
            if ($rv === FALSE) continue;
            $obj = unserialize($rv);
            if (!($obj instanceof OAuthConsumer)) continue;
            $consumers[]=$obj;
        }
        return $consumers;
    }/*}}}*/

    function list_tokens($username = '') {/*{{{*/
        $key=dba_firstkey($this->dbh);
        $tokens=array();
        $usertokens=array();
        while ($key != false) {
            if (!strncmp($key,"userT_",6))
                $tokens[] = $key;
            $key = dba_nextkey($this->dbh);
        }
        foreach ($tokens as $token) {
            $rv = dba_fetch($token, $this->dbh);
            if ($rv === FALSE) continue;
            $data = unserialize($rv);
            if ('userT_'.$data['token'] != $token) continue;
            if (!empty($username) && $data['user'] != $username) continue;
            $usertokens[]=array('consumer_key' => $data['consumer'], 'token_key' => $data['token'], 'user' => $data['user']); 
            // TODO: get_token_by_key() ; lookup_token..() for object/secret
        }
        return $usertokens;
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

    function cleanup_nonce() {/*{{{*/
        $key = dba_firstkey($this->dbh);
        $now=time();
        $handle_later = array();
        while ($key != false) {
        # clean up old-NONCEs -> oauth_timestamp ;; OAuthServer->timestamp_threshold (300 sec)
        # give it some extra hour(s) eg. server changes time-zones...
            if (!strncmp($key,"nonce_",6) && dba_fetch($key, $this->dbh) + 3900 < $now) 
                $handle_later[] = $key;
        # same for old session-tokens.
            if (!strncmp($key,"session_",8) && $rv=dba_fetch($key, $this->dbh)) {
                $data=unserialize($rv);
                if ($data['created'] + 3900 < $now) 
                    $handle_later[] = $key;
            }
            $key = dba_nextkey($this->dbh);
        }
        foreach ($handle_later as $key) {
            dba_delete($key, $this->dbh);
        }
    }/*}}}*/

    function lookup_nonce($consumer, $token, $nonce, $timestamp) {/*{{{*/
        if (dba_exists("nonce_$nonce", $this->dbh)) {
            return TRUE;
        } else {
            dba_insert("nonce_$nonce", time(), $this->dbh);
            $this->cleanup_nonce();
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
        $user=($this->lookup_user($consumer->key, $token->key));
        if (empty($user) || is_array($user)) { 
          return FALSE;
        }
        $actok = $this->new_token($consumer, 'access');
        dba_delete("request_" . $token->key, $this->dbh);
        $this->del_usermap('userX', $token->key); // delete request-token/consumer link
        $this->del_usermap('userT', $token->key);
        $this->new_usermap($user, 'userT', $consumer->key, $actok->key);
        return $actok;
    }/*}}}*/

}/*}}}*/


class DokuOAuthSignatureMethod_RSA_SHA1 extends OAuthSignatureMethod_RSA_SHA1 {/*{{{*/
  // TODO: generate, save/load CERTs

  public function fetch_private_cert(&$request) {/*{{{*/
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
  }/*}}}*/

  public function fetch_public_cert(&$request) {/*{{{*/
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
  }/*}}}*/
}/*}}}*/

/* vim: set ts=4 sw=4 et foldmethod=marker enc=utf-8 : */
