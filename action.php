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
            'date'   => '2008-10-09',
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
                $user=$doku_server->get_dokuwiki_user($consumer, $token);

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
        $map_token=false; 
        $user_notified=false; 
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
                    case 'addconsumer':
                        $handled=true;
                        $consumer_key="robin";
                        $consumer_sec="geheim";
                        $consumer_cal="http://localhost/callbackdump.php";
                        $consumer_cal=NULL;
                        break; // TODO 
                        $doku_server->create_consumer($consumer_key, $consumer_sec, $consumer_cal);
                        $acllimit=array('suid' => '', 'users'=>NULL, 'timeout' => 0);
                        $doku_server->map_consumer($consumer_key, $acllimit);
                        break;

                    case 'accesstoken':
                        $this->_debug('access');
                        $handled=true;
                        $req = OAuthRequest::from_request();

                        # DokuOAuthDataStore for access tokens:
                        #  - tests if given request-token has been (authorized by|mapped to) a user 
                        #  - if not user found: `fetch_access_token()` returns NULL!
                        #     else the request-token is exchanged for an access-token, retraining the user mapping
                        # fetch_access_token requires a valid oauth signature.
                        $token = $doku_server->fetch_access_token($req);
                        if ($token && $req instanceof OAuthToken)
                            print $token;

                        exit(0);
                        break;

                    case 'cancel':
                        $handled=true;
                        $req=$doku_server->load_session($dwoauthnonce,&$token);
                        $op=$req->get_parameters();
                        $consumer_key=$op['oauth_consumer_key'];
                        $consumer = $doku_server->get_consumer_by_key($consumer_key);
                        $this->redirect($consumer->callback_url, array());
                        break;

                    case 'resume':
                        $req=$doku_server->load_session($dwoauthnonce,&$token);
                        if (!isset($req)) {
                            trigger_error('Failed to load/resume session.');
                            exit(0);
                        }
                        $userconfirmed=$_REQUEST['userconfirmed']?true:false;
                        $trustconsumer=$_REQUEST['trustconsumer']?true:false;
                    case 'authorize':
                        if (!isset($req)) {
                        # TODO: allow to enter here to log-in with or without 'oauth_token' 
                        # fake $req and $token 
                        #
                        # $req=new OAuthRequest();
                        # set parameter 'oauth_consumer_key'
                        #
                        # check if already mapped!
                        }
                    case 'requesttoken': # TODO: allow to get an unmapped request-token.. (read oauth_token and oauth_callback when re-entering)
                        $this->_debug('authorize');
                        $handled=true;

                        if (!isset($req)) {
                            $req = OAuthRequest::from_request();
                        }
                        if (!($req instanceof OAuthRequest)) {
                            trigger_error('Can not parse oAuth request.');
                            exit(0);
                        }

                        $op=$req->get_parameters();
                        $consumer_key=$op['oauth_consumer_key'];

                        if (!($token instanceof OAuthToken)) {
                            # this requires a valid oauth signature!
                            $token = $doku_server->fetch_request_token($req);
                        }

                        # check-consumer_acl() honors dokuwiki-auth
                        $user = $this->check_consumer_acl($doku_server, $consumer_key);

                        if (!empty($user)) {
                            $map_token=true; 
                        } else if (1) { // return unauthorized token ?!
                            $secpass=$doku_server->save_session($req,$token);
                            $user_notified=true; 
                        /*
                            if (!($helper = &plugin_load('helper', 'oauth'))){
                                trigger_error('oauth plugin helper is not available.');
                                exit(0);
                            }
                            $helper->oauthLogon($secpass,2,3);
                         */
                            // LOGIN PAGE WORKAROUND
                            global $ID; $ID="OAUTHPLUGIN:".rawurlencode($secpass);
                            $map_token=false; $handled=false; $event->data="login"; // XXX
                            // END LOGIN PAGE WORKAROUND
                            break; 
                        } else {
                            $map_token=false; 
                            $user_notified=false; 
                        }

                        if ($map_token && !$userconfirmed) {
                            if (!$this->check_consumer_confirm($doku_server, $user, $consumer_key, $token)) {
                                if (1) { // return unauthorized token ?!
                                    if (!($helper = &plugin_load('helper', 'oauth'))){
                                        trigger_error('oauth plugin helper is not available.');
                                        exit(0);
                                        break;
                                    }
                                    $secpass=$doku_server->save_session($req,$token);
                                    $helper->oauthConfirm($secpass,2,3);
                                    $user_notified=true; 
                                    break;
                                } else {
                                    $map_token=false; 
                                    $user_notified=false; 
                                }
                            }
                        }

                        # TODO: test if token is already mapped..

                        if ($map_token && $trustconsumer) {
                            // save confirmation for next time.. (TODO: unless SUID ?!)
                            $cs=$doku_server->get_consumer_settings($consumer_key); 
                            if (!is_array($cs['trusted'])) $cs['trusted']=array();
                            $cs['trusted']=array_unique(array_merge($cs['trusted'],array($user)));
                            $doku_server->set_consumer_settings($consumer_key,$cs); 
                        }

                        if ($map_token) {
                            $doku_server->map_user($user,$consumer_key, $token->key);
                        }

                        if (!$user_notified) {
                            ; // send email ?! ..
                        }

                        // redirect back to $consumer->callback_url add $request-token.
                        $consumer = $doku_server->get_consumer_by_key($consumer_key);
                        if (!empty($consumer->callback_url)) {
                            $this->redirect($consumer->callback_url, array(
                                    'oauth_token'=>rawurlencode($token->key),
                                    'oauth_token_secret'=>rawurlencode($token->secret)
                                    # TODO: include xoauth parameters ?!
                                    ));
                        } else  {
                            print $token;
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

    private function check_consumer_acl($doku_server, $consumer_key) {/*{{{*/
        $acllimit = $doku_server->get_consumer_acl($consumer_key);
        $user=NULL;
        if (is_array($acllimit) && !empty($acllimit['suid'])) {
           $user = $acllimit['suid'];
           return $user;
        } 
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
