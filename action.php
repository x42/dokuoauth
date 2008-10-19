<?php
/**
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Robin Gareus <robin@gareus.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_oauth extends DokuWiki_Action_Plugin {

    /**
     * return some info
     */
    function getInfo(){
        return array(
            'author' => 'Robin Gareus',
            'email'  => 'robin@gareus.org',
            'date'   => '2008-10-15',
            'name'   => 'oauth',
            'desc'   => 'Authorize User requests by oAuth',
            'url'    => 'http://mir.dnsalias.com/wiki/dokuoauth',
        );
    }

    /**
     * register the eventhandlers
     */
    function register(&$contr){
        $contr->register_hook('ACTION_ACT_PREPROCESS',
                              'BEFORE',
                              $this,
                              'handle_act_preprocess');

        $contr->register_hook('ACTION_ON_AUTH',
                              'BEFORE',
                              $this,
                              'handle_act_authhook');

        $contr->register_hook('TPL_ACT_UNKNOWN',
                              'BEFORE',
                              $this,
                              'handle_act_output');
    }

    /**
     *
     */
    function handle_act_authhook(&$event, $param){
        if (is_array($_REQUEST['do']) && !empty($_REQUEST['do']['oauth'])) return; // skip requests to oauth-API

        if (!empty($_REQUEST['oauth_signature'])) {
            require_once("dokuoauth.php");
            $user='';
            // verify signature - check consumer and access token
            try {
                $req = OAuthRequest::from_request();
                list($consumer, $token) = $doku_server->verify_request($req);
                $user=$doku_server->get_dokuwiki_user($consumer->key, $token->key);

            } catch (OAuthException $e) {
                print($e->getMessage() . "\n<hr />\n");
                print_r($req);
                $this->_debug("oauth error:\n".$e->getMessage()."\n".print_r($req, true));
                die();
            }

            if (empty($user)) $this->_debug('oAuth: empty user name.');
            if (empty($user)) return;

            // -> set username for this session
            $_SERVER['REMOTE_USER'] = $user;
            global $USERINFO;
            global $auth;
            $USERINFO = $auth->getUserData($user);
            if (!is_array($USERINFO)) {
                $_SERVER['REMOTE_USER'] = "";
                $this->_debug('oAuth: could not find user: '.$user);
            } 
            else $this->_debug('oAuth: set-user: '.$user);
        }
    }


# FLOW;
# - [admin,user,auto] add consumer 
#     [admin] may set suid tokens along with user
#     [admin] may set trust-level of consumer-keys (restrict to users, group)
#     [user] may whitelist consumer for his account and set an ACL limit for the consumer and/or [req|access] token!
#     [anon-consumers] may add themselves with a callback uri 
# - get request-token
#    [auto] if consumer is suid (no-browser - return token or redirect to consumer)
#    [auto] if user is logged-on and has whitelisted the consumer -> redirect to consumer
#    [user] if user is logged-on -> as for confirmation  -> redirect to consumer
#    [user] log-in (remember consumer) -> try-again to check/ask for confirmation -> redirect to consumer
#
# - [auto] get access-token 
#    check if request token is valid for this consumer and has a dokuwiki user mapped to it..  
#
    /**
     *
     */
    function handle_act_preprocess(&$event, $param){
        $handled=false;
        $user_notified=false;  // XXX
        $dwoauthnonce=rawurldecode($_REQUEST['dwoauthnonce']);

        // LOGIN PAGE WORKAROUND
        global $ID; 
        if ($event->data=='login' && !strncasecmp($ID,"OAUTHPLUGIN:",12)) {
            $dwoauthnonce=rawurldecode(substr($ID,12));
            unset($event->data);
            $event->data=array();
            $event->data['oauth']='resume';
        }
        // END LOGIN PAGE WORKAROUND

        if (!empty($event->data['oauth'])) {
            // interactive oAuth - admin
            require_once("dokuoauth.php");
            try {
                switch (trim($event->data['oauth'])) {

                    case 'cancel':
                        $this->_debug('ACT: cancel');
                        $handled=true;
                        $consumer_key='';
                        if($ses=$doku_server->load_session($dwoauthnonce))
                            $consumer_key=$ses['consumer_key'];
                        if (!empty($consumer_key)) {
                            $consumer = $doku_server->get_consumer_by_key($consumer_key);
                            if (!empty($consumer) && ($req instanceof OAuthConsumer)) {
                                if (!empty($consumer->callback_url)) {
                                    $this->redirect($consumer->callback_url, array());
                                    break;
                                }
                            }
                        }
                        # TODO: $helper->cancelled(); page
                        break;

                    case 'addconsumer':
                        $this->_debug('ACT: addconsumer');
                        $handled=true;
                        $consumer_key=$_REQUEST['consumer_key'];
                        $consumer_sec=$_REQUEST['consumer_secret'];
                        $consumer_cal=$_REQUEST['callback_url'];
                        if (empty($consumer_cal)) $consumer_cal=NULL;
                        if (empty($consumer_key)) {
                            ; // TODO error
                            $this->_debug('addconsumer: empty consumer-key.');
                            break; 
                        }
                        // TODO: check if it already exists !
                        if ($doku_server->get_consumer_by_key($consumer_key)) {
                            ; // TODO error
                            $this->_debug('addconsumer: consumer already exists.');
                            break;
                        }
                        $doku_server->create_consumer($consumer_key, $consumer_sec, $consumer_cal);
                        $acllimit=array('suid' => '', 'users'=>NULL, 'timeout' => 0);
                        $doku_server->map_consumer($consumer_key, $acllimit);
                        break;

                    case 'accesstoken': // exchange [authorized] request-token for an access-token.
                        $this->_debug('ACT: accesstoken');
                        $handled=true;
                        $req = OAuthRequest::from_request();

                        # DokuOAuthDataStore for access tokens:
                        #  - tests if given request-token has been (authorized by|mapped to) a user 
                        #  - if not user found: `fetch_access_token()` returns NULL!
                        #     else the request-token is exchanged for an access-token, retraining the user mapping
                        $token = $doku_server->fetch_access_token($req);
                        if ($token && $token instanceof OAuthToken)
                            print $token;
                        else {
                            #trigger_error('request token is invalid not not authorized.'); 
                            $this->_debug("failed to exchange request for access token.");
                        }
                        exit(0);

                    case 'requesttoken':  // request a request-token
                        $this->_debug('ACT: requesttoken');
                        $handled=true;
                        $req = OAuthRequest::from_request();
                        $token = $doku_server->fetch_request_token($req);

                        $op=$req->get_parameters();
                        $consumer_key=$op['oauth_consumer_key'];

                        # auto-authorize suid tokens
                        $user = $this->check_consumer_acl($doku_server, $consumer_key);
                        if (!empty($user)) {
                            $doku_server->map_user($user,$consumer_key, $token->key);
                            $doku_server->map_requesttoken($consumer_key, $token->key); // will be deleted when getting access-token.
                        } else {
                            //remember consumer key for this token until authorization.
                            $doku_server->map_requesttoken($consumer_key, $token->key);
                        }
                        print $token;
                        exit(0);

                    case 'resume':
                        $this->_debug('ACT: resume authentication');
                        $ses=$doku_server->load_session($dwoauthnonce);
                        if (!is_array($ses)) {
                            trigger_error('can not resume this session.'); 
                            exit(0);
                        }
                        $consumer_key=$ses['consumer_key'];
                        $token_key=$ses['token_key'];
                        $callback_url=$ses['oauth_callback'];

                        $userconfirmed=$_REQUEST['userconfirmed']?true:false;
                        $trustconsumer=$_REQUEST['trustconsumer']?true:false;
                        $user_notified=true; // XXX
                    case 'authorize':
                        $this->_debug('ACT: authorize');
                        if (empty($token_key)) {
                            $token_key=$_REQUEST['oauth_token'];
                        }

                        if (empty($token_key)) {
                            // TODO -> ask user for token!
                            trigger_error('no oauth_token given for authorization.'); exit(0);
                        }
                        if (empty($consumer_key)) {
                            # TODO parse or lookup consumer for this token ...
                            #$consumer_key=$_REQUEST['oauth_consumer_key'];
                            $consumer_key=$doku_server->get_consumer_by_requesttoken($token_key);
                        }
                        if (empty($callback_url)) {
                            $callback_url = $REQUEST['oauth_callback'];
                        }

                    case 'XXXauth': 
                        $this->_debug('ACT: authorize step 2 t:'.$token_key.' c:'.$consumer_key);
                        $handled=true; // XXX

                        # we need a request-token-key and consumer-key 
                        if (empty($token_key) || empty($consumer_key)) {
                            trigger_error('insufficient info to grant token authorization.');
                            exit(0);
                        }

                        $user = $doku_server->get_dokuwiki_user($consumer_key, $token_key);
                        if (!empty($user)) {
                            trigger_error('token is already authorized for user:'.$user);
                            exit(0);
                        }

                        $user = $this->check_consumer_acl($doku_server, $consumer_key);
                        if (empty($user)) {
                            $user = $this->check_doku_auth($doku_server, $consumer_key);
                        }

                        if (empty($user)) {
                            $secpass=$doku_server->save_session(array('consumer_key' =>$consumer_key, 'token_key' => $token_key, 'oauth_callback' => $callback_url));
                            $user_notified=true;  // XXX
                        /*
                            if (!($helper = &plugin_load('helper', 'oauth'))){
                                trigger_error('oauth plugin helper is not available.');
                                exit(0);
                            }
                            $helper->oauthLogon($secpass,2,3);
                         */
                            // LOGIN PAGE WORKAROUND
                            global $ID; $ID="OAUTHPLUGIN:".rawurlencode($secpass);
                            $handled=false; $event->data="login"; // XXX
                            // END LOGIN PAGE WORKAROUND
                            break; 
                        }

                        if (!$userconfirmed) {
                            if (!$this->check_consumer_confirm($doku_server, $user, $consumer_key, $token)) {
                                $secpass=$doku_server->save_session(array('consumer_key' =>$consumer_key, 'token_key' => $token_key, 'oauth_callback' => $callback_url));
                                #$helper->oauthConfirm($secpass,array('consumer_key' =>$consumer_key, 'token_key' => $token_key, 'oauth_callback' => $callback_url));
                                #global $ID; $ID="OAUTHPLUGIN:".rawurlencode($secpass);
                                global $PAGE; $PAGE="oauth";
                                $handled=false; $event->data="oauthconfirm"; // XXX
                                $event->preventDefault();
                                #$event->result = true;
                                #$event->stopPropagation();
                                $user_notified=true;  // XXX
                                break;
                            }
                        }

                        if ($trustconsumer) {
                            // save confirmation for next time.. (TODO: unless SUID ?!)
                            $cs=$doku_server->get_consumer_settings($consumer_key); 
                            if (!is_array($cs['trusted'])) $cs['trusted']=array();
                            $cs['trusted']=array_unique(array_merge($cs['trusted'],array($user)));
                            $doku_server->set_consumer_settings($consumer_key,$cs); 
                        }

                        $doku_server->map_user($user, $consumer_key, $token_key);

                        # NOTE: userX (consumer/request-token map for 'resume' auth is removed when exchanging the token!
                        # we could also remove it now with map_user..

                        if (!$user_notified) { // XXX
                            ; // send email ?! ..
                        }

                        # redirect back to consumer 

                        if (empty($callback_url)) {
                            $consumer = $doku_server->get_consumer_by_key($consumer_key);
                            $callback_url=$consumer->callback_url;
                        }

                        if (!empty($callback_url)) {
                            # TODO: include xoauth parameters ?!
                            $this->redirect($callback_url, array('oauth_token'=>rawurlencode($token_key)));
                        } else  {
                            $this->_debug("token-auth suceeded.");
                            echo ("request token $token_key authorized.");
                            #TODO: tell user to go back to consumer. $token is now authorized ..
                            exit(0);
                        }
                        break;

                    default:
                        break;
                }
            } catch (OAuthException $e) {
                print($e->getMessage() . "\n<hr />\n");
                print_r($req);
                $this->_debug("oauth error:\n".$e->getMessage()."\n".print_r($req, true));
                die();
            }
        }

        if ($handled) {
            #$this->_debug('handled');
            #$event->stopPropagation();
            #$event->preventDefault();
            #$event->result = true;
            #$event->data="show";
            exit(0);
        }
    }

    function handle_act_output(&$event){
        if ($event->data=='oauthconfirm') {
            if (!($helper = &plugin_load('helper', 'oauth'))){
                trigger_error('oauth plugin helper is not available.');
                exit(0);
                break;
            }
            $helper->oauthConfirm($secpass,array('consumer_key' =>$consumer_key, 'token_key' => $token_key, 'oauth_callback' => $callback_url));
            #$event->result = true;
            #$event->stopPropagation();
            $event->preventDefault();
            return true;
        }
    }

    private function check_consumer_acl($doku_server, $consumer_key) {/*{{{*/
        $acllimit = $doku_server->get_consumer_acl($consumer_key);
        $user=NULL;
        if (is_array($acllimit) && !empty($acllimit['suid'])) {
           $user = $acllimit['suid'];
           return $user;
        } 
        return $user;
    }/*}}}*/

    private function check_doku_auth($doku_server, $consumer_key) {/*{{{*/
        $acllimit = $doku_server->get_consumer_acl($consumer_key);
        $user=NULL;
        if ($_SERVER['REMOTE_USER']) {
            $user=$_SERVER['REMOTE_USER'];
            $this->_debug("dokuwiki already authenticated user: $user");
        } else if (auth_login("","",false,true)) {
        #          auth_login($_REQUEST['u'],$_REQUEST['p'],$_REQUEST['r'],false,true); # workaround for workaround above ;)
            $this->_debug("user logged-in via COOKIE: $user");
            global $USERINFO;
            $user=$_SERVER['REMOTE_USER'];
        }
        // TODO: check group(s), not is_admin, etc.
        if (is_array($acllimit['users']) && !in_array($user, $acllimit['users'])) { 
            $this->_debug("denied user '$user' for this consumer.");
            msg("Consumer is not allowed access to this user.");
            #auth_logoff();
            $user=NULL;
        }

        return $user;
    }/*}}}*/

    private function check_consumer_confirm($doku_server, $user, $consumer_key, $request_token) {/*{{{*/
        $acllimit = $doku_server->get_consumer_acl($consumer_key);
        if (is_array($acllimit) && !empty($acllimit['suid'])) return true;

        // check database ... for user <> consumer  user-whitelist (auto-confirm)
        $cs=$doku_server->get_consumer_settings($consumer_key); 
        if (!is_array($cs['trusted']) || !in_array($user, $cs['trusted'])) return false;

        return true; 
    }

    private function redirect($uri, $params) {/*{{{*/
        if (!empty($params)) { 
            $q = array();
            foreach ($params as $name=>$value)
                $q[] = $name.'='.$value;
            
            $q_s = implode('&', $q);
            if (strpos($uri, '?'))
                $uri .= '&'.$q_s;
            else
                $uri .= '?'.$q_s;
        }
        // simple security - multiline location headers can inject all kinds of extras
        $uri = preg_replace('/\s/', '%20', $uri);
        if (strncasecmp($uri, 'http://', 7) && strncasecmp($uri, 'https://', 8)) {       
            if (strpos($uri, '://'))
                throw new OAuthException('Illegal protocol in redirect uri '.$uri);
            $uri = 'http://'.$uri;
        }
            
        header('HTTP/1.1 302 Found');
        header('Location: '.$uri);
        echo '';
        exit(0);
    } /*}}}*/

    /*{{{*/
    private function _debug ($m = null){
        $PSdebug= true; //XXX
        $PSlogfile= '/tmp/oAuth.debug';
        if (! isset($PSdebug) || $PSdebug === false) return;

        if (! is_writable(dirname($PSlogfile)) &! is_writable($PSlogfile)){
            header("HTTP/1.1 500 Internal Server Error");
            echo 'Cannot write to debug log: ' . $PSlogfile;
            return;
        }
        $vhost=DOKU_URL;
        error_log($vhost.' '.date("c ").$m."\n", 3, $PSlogfile);
    } 
    /*}}}*/

}
//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
