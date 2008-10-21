<?php
/**
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Robin Gareus <robin@gareus.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class action_plugin_oauth extends DokuWiki_Action_Plugin {

    var $_outargs = NULL;

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
                $this->_log("oauth error:\n".$e->getMessage()."\n".print_r($req, true));
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
                $_SERVER['REMOTE_USER'] = ""; // after _log() ?
                $this->_debug('oAuth: could not find user: '.$user);
                $this->_log("user '$user' not found.");
            } 
            else { 
                $this->_debug('oAuth: set-user: '.$user);
                $this->_log("granted access.");
            }
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
        $handled=false;  // continue with dokuwiki..
        $finished=false; // request finished - exit after this function
        $user_notified=false;  // TODO
        $dwoauthnonce=rawurldecode($_REQUEST['dwoauthnonce']);

        // LOGIN PAGE WORKAROUND XXX
        global $ID; 
        if ($event->data=='login' && !strncasecmp($ID,"OAUTHPLUGINNONCE:",17)) {
            $dwoauthnonce=rawurldecode(substr($ID,17));
            unset($event->data);
            $event->data=array();
            $event->data['oauth']='resume';
            $this->_debug('intercepted oauth login');
        }
        // END LOGIN PAGE WORKAROUND XXX

        if (trim($event->data) == 'oauth') {
            $handled=true;
            $event->data="oauthinfo";
        }
        else if (!empty($event->data['oauth'])) {
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
                                    $finished=true;
                                    break;
                                }
                            }
                        }
                        $event->data="oauthcancel";
                        break;

                    case 'delconsumer':
                        $doit=true;
                        $consumer_key=$_REQUEST['consumer_key'];
                        $this->_debug("remove Consumer: $consumer_key");
                        if (empty($consumer_key)) {
                            $doit=false;
                            msg("empty consumer key.",-1);
                        }
                        if ($doit && !auth_isadmin() && !($this->getConf('manager_admin') && auth_ismanager())) {
                            $acllimit = $doku_server->get_consumer_acl($consumer_key);
                            if (!is_array($acllimit) 
                                || $acllimit['owner'] != $_SERVER['REMOTE_USER'] 
                                || empty($_SERVER['REMOTE_USER'])) {
                                // TODO PERMISSION DENIED
                                #$handled=true; 
                                #$event->data="oautherror"; // TODO go back to clist?
                                #$this->_outargs['errormessage'] = 'permission denied.';
                                #break;
                                msg("permission denied to delete consumer.",-1);
                                $doit=false;
                            }
                        }
                        if ($doit && !$doku_server->get_consumer_by_key($consumer_key)) {
                                msg("unknown consumer key. maybe it has been deleted already.",-1);
                                $doit=false;
                        }
                        if ($doit) {
                            $doku_server->delete_consumer($consumer_key);
                            msg("removed Consumer: $consumer_key");
                        }
                        # continue to list

                    case 'clist':
                        $handled=true; 
                        $event->data="oauthlist";
                        $this->_outargs=array();
                        $consumers=$doku_server->list_consumers();
                        // map to $this->_outargs; include links to cinfo, strip secrets unless auth_ismanager()
                        foreach ($consumers as $c) {
                            $acllimit = $doku_server->get_consumer_acl($c->key);
                            unset($acllimit);
                            // TODO if not is_admin() .. remove /secret/ information
                            $this->_outargs[]=array(
                                'key' => $c->key,
                                'user' => '-', # SUID ?
                                'type' => 'consumer',
                                'secret' => $c->secret,
                                'acllimit' => $acllimit,
                                'action' => array( 'delconsumer&consumer_key=' => 'Delete', 'cinfo&consumer_key=' => 'Inspect')
                            );
                        }
                        break;

                    case 'deltoken':
                        $doit=true;
                        $token_key=$_REQUEST['token_key'];
                        $this->_debug("remove Token: $token_key");
                        if (empty($token_key)) {
                            $doit=false;
                            msg("empty token key.",-1);
                        }
                        if ($doit && !auth_isadmin() && !($this->getConf('manager_admin') && auth_ismanager())) {
                            $owner = $doku_server->get_token_user($token_key);
                            if (empty($owner)) {
                                $doit=false; // XXX - delete those after they expire..
                                $this->_debug("found yet unmapped request token.");
                            } else
                            if ($owner != $_SERVER['REMOTE_USER'] || empty($_SERVER['REMOTE_USER'])) {
                                msg("permission denied to delete consumer.",-1);
                                $doit=false;
                            }
                        }
                        if ($doit && !$doku_server->get_token_by_key(NULL, $token_key)) {
                            msg("token does not exist.",-1);
                            $doit=false;
                        }
                        if ($doit && get_token_by_key(NULL, $token_key)) {
                            $doku_server->unmap_user($token_key);
                            msg("removed token: $token_key");
                        }
                    #   break;

                    case 'tlist':
                        $handled=true; 
                        $event->data="oauthlist";
                        if (auth_isadmin() || ($this->getConf('manager_admin') && auth_ismanager())) {
                            $userfilter=$_REQUEST['userfilter']; # TODO - admin-form
                            msg("admin mode - showing tokens of all users",0);
                        } else {
                            $userfilter=trim($_SERVER['REMOTE_USER']);
                            if (empty($userfilter)) {
                                // permission denied.
                                $event->data="oautherror"; // TODO go back to list-form?
                                $this->_outargs['errormessage'] = 'you need to be logged in to view your tokens.';
                                break;
                            }
                        }
                        $this->_outargs=array();
                        foreach($doku_server->list_usertokens($userfilter) as $token) {
                        // TODO lookup userX mappings?
                            $ti=$doku_server->get_token_by_key($token['consumer_key'], $token['token_key']); 
                            $this->_outargs[]=array(
                                'user' => $token['user'], 
                                'type' => $ti['type'],
                                'action' => array ( 'deltoken&token_key=' => 'Revoke'),
                                'key' => $ti['obj']->key,
                                'secret' => $ti['obj']->secret # XXX strip secrets unless configued.
                            );
                        }
                        break;

                    case 'debug':
                        die('you are not debugging.'); # XXX
                        $finished=true; 
                        print_r($doku_server->list_consumers()); # XXX - shows secrets of the consumer !
                        print "<br/>\n";
                        print "<br/>\n";
                        print_r($doku_server->list_usertokens($_SERVER['REMOTE_USER']));
                        print "<br/>\n";
                        print "<br/>\n";
                        foreach($doku_server->list_usertokens('') as $token) { # XXX lists ALL tokens
                            print 'token for user :'.$token['user'].' - ';
                            print_r($doku_server->get_token_by_key($token['consumer_key'], $token['token_key'])); # XXX - shows token secrets
                            print "<br/>\n";
                        }
                        break;

                    case 'addconsumer':
                        $this->_debug('ACT: addconsumer');
                        $handled=true;
                        $consumer_key=$_REQUEST['consumer_key'];
                        $consumer_sec=$_REQUEST['consumer_secret'];
                        $consumer_cal=$_REQUEST['callback_url'];
                        if (empty($consumer_cal)) $consumer_cal=NULL;
                        if (empty($consumer_key)) {
                            $event->data="oauthaddconsumer"; 
                            $this->_debug('addconsumer: empty consumer-key.'); 
                            $this->_outargs=array('consumer_key' => '', 'consumer_secret' => $consumer_sec, 'callback_url' => $consumer_cal);
                            $this->_outargs['errormessage'] = 'addconsumer: empty consumer key.';
                            break; 
                        }
                        $finished=true;

                        if ($doku_server->get_consumer_by_key($consumer_key)) {
                            ; // TODO: error or ignore ?
                            if ($_REQUEST['feedback']) {
                                $finished=false;
                                msg('consumer add: A consumer with this key already exists.', -1);
                                $this->_outargs=array('consumer_key' => '', 'consumer_secret' => $consumer_sec, 'callback_url' => $consumer_cal);
                                $event->data="oauthaddconsumer"; 
                            }
                            $this->_debug('addconsumer: consumer already exists.');
                            break;
                        }
                        // TODO  check ACL is_admin(), allow to create suid tokens, ...
                        $doku_server->create_consumer($consumer_key, $consumer_sec, $consumer_cal);
                        $acllimit=array('suid' => '', 'users'=>NULL, 'timeout' => 0, 'owner' => $_SERVER['REMOTE_USER']);
                        $doku_server->map_consumer($consumer_key, $acllimit);

                        if ($_REQUEST['feedback']) {
                            $finished=false;
                            $event->data="oautherror"; // TODO go back to add-form.
                            $this->_outargs['errormessage'] = 'scratch that error. Consumer '.$consumer_key.' was added suceccfully.';
                        }
                        break;

                    case 'accesstoken': // exchange [authorized] request-token for an access-token.
                        $this->_debug('ACT: accesstoken');
                        $finished=true;
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
                        break;

                    case 'requesttoken':  // request a request-token
                        $this->_debug('ACT: requesttoken');
                        $finished=true;
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
                        break;

                    case 'info': // general information on oAuth
                        $handled=true; 
                        $event->data="oauthinfo";
                        break;

                    case 'cinfo': // show consumer info (optionally back to authorize-token)
                        $handled=true; 
                        $secpass=NULL;
                        $consumer_key='';
                        if (!empty($dwoauthnonce)) {
                            $ses=$doku_server->load_session($dwoauthnonce);
                            if (is_array($ses)) {
                                $secpass=$doku_server->save_session($ses);
                                $consumer_key=$ses['consumer_key'];
                            } else {
                                // ignore (reload) ? XXX
                                $this->_debug('consumer info: empty session');
                            }
                        }
                        if (empty($consumer_key))
                            $consumer_key=$_REQUEST['consumer_key'];

                        if (empty($consumer_key)) {
                                $event->data="oautherror";
                                $this->_outargs['errormessage'] = 'consumer info: empty consumer key.';
                                break;
                        }

                        if ($consumer=$doku_server->get_consumer_by_key($consumer_key)) {
                            $event->data="oauthcinfo";
                            $this->_outargs=array('consumer_key' => $consumer->key, 'callback_url' => $consumer->callback_url);
                            $this->_outargs['acllimit'] = $doku_server->get_consumer_acl($consumer->key);
                            // TODO if not is_admin() .. remove /secret/ information from acllimit ?!
                            if (auth_isadmin() || ($this->getConf('manager_admin') && auth_ismanager())) { // XXX
                                $this->_outargs['consumer_secret'] = $consumer->secret; 
                            } else {
                                $this->_outargs['consumer_secret'] = '&lt;<em>hidden</em>&gt;'; 
                            }
                            if (!empty($secpass)) 
                                $this->_outargs['secpass'] = $secpass;
                        } else {
                            $event->data="oautherror";
                            $this->_outargs['errormessage']= "Consumer is unknown.";
                        }
                        break;

                    case 'resume':
                        $this->_debug('ACT: resume authentication');
                        $ses=$doku_server->load_session($dwoauthnonce);
                        if (!is_array($ses)) {
                            // TODO make error
                            #$handled=true;
                            #$event->data="oautherror";
                            #$this->_outargs['errormessage'] = 'can not resume this session.';
                            #break;
                            trigger_error('Invalid token. Can not resume this session. Try hitting your browser\'s "back" button.'); 
                            exit(0);
                        }
                        $consumer_key=$ses['consumer_key'];
                        $token_key=$ses['token_key'];
                        $callback_url=$ses['oauth_callback'];

                        $userconfirmed=$_REQUEST['userconfirmed']?true:false;
                        $trustconsumer=$_REQUEST['trustconsumer']?true:false;
                        $user_notified=true; // TODO
                    case 'authorize':
                        $this->_debug('ACT: authorize');
                        if (empty($token_key)) {
                            $token_key=$_REQUEST['oauth_token'];
                        }

                        if (empty($token_key)) {
                            // TODO -> ask user for token! token-add/admin form
                            #$handled=true;
                            #$event->data="oauthtoken";
                            #break;
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

                    #case 'XXXauth': 
                        $this->_debug('ACT: authorize step 2 t:'.$token_key.' c:'.$consumer_key);
                        $finished=true; 

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
                            // LOGIN PAGE WORKAROUND XXX
                            global $ID; $ID="OAUTHPLUGINNONCE:".rawurlencode($secpass);
                            $finished=false; $handled=true; $event->data="login";
                            $this->_debug('dropping to login..');
                            return; /// don't $event->preventDefault(); 'login' is the default ;)
                            // END LOGIN PAGE WORKAROUND XXX
                            break; 
                        }

                        if (!$userconfirmed) {
                            if (!$this->check_consumer_confirm($doku_server, $user, $consumer_key, $token)) {
                                $secpass=$doku_server->save_session(array('consumer_key' =>$consumer_key, 'token_key' => $token_key, 'oauth_callback' => $callback_url));
                                $this->_outargs=array('secpass' => $secpass, 'consumer_key' => $consumer_key, 'token_key' => $token_key, 'oauth_callback' => $callback_url);
                                $this->_debug('heading to confirm..');
                                $finished=false; $handled=true; 
                                $event->data="oauthconfirm"; 
                                global $ACT; $ACT="oauthconfirm"; // override default as well (in case we intercepeted a login)
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

                        if (!$user_notified) {
                            ; // TODO send email is configured..
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
                            #finished=false;
                        }
                        break;

                    default:
                        break;
                }
            } catch (OAuthException $e) {
                print($e->getMessage() . "\n<hr />\n");
                print_r($req);
                $this->_debug("oauth error:\n".$e->getMessage()."\n".print_r($req, true));
                $this->_log("oauth error:\n".$e->getMessage()."\n".print_r($req, true));
                die();
            }
        }

        if ($finished) {
            $this->_debug('over and out.');
            exit(0);
        }
        if ($handled) {
            $this->_debug('handled action');
            #$event->stopPropagation();
            $event->preventDefault();
            #$event->result = true;
            #return true;
        }
    }

    function handle_act_output(&$event){
        $handled=false;
        $this->_debug('output event: '.print_r($event, true));
        if (!in_array(trim($event->data), array(
                'oauthconfirm', 'oautherror',
                'oauthcancel', 'oauthcinfo',
                'oauthinfo', 'oauth', 'oauthlist',
                'oauthaddconsumer'
           ))) {
            return false;
        }

        if (!($helper = &plugin_load('helper', 'oauth'))){
            trigger_error('oauth plugin helper is not available.');
            exit(0);
            break;
        }
        switch (trim($event->data)) {
            case 'oautherror':
                // TODO 
                $helper->oauthToolbar();
                #$helper->oauthError($this->_outargs);
                print('<p><b>Oauth Error:</b>&nbsp;'.$this->_outargs['errormessage'].'</p>');
                $handled=true;
                break;
            case 'oauthcancel':
                $helper->oauthToolbar();
                print('<p>Oauth Transaction Cancelled. I don\'t know what to do next. Have nice day.</p><p> truly yours,<br/> OAuth plugin</p>');
                $handled=true;
                break;
            case 'oauth':
            case 'oauthinfo':
                $helper->oauthInfo();
                $handled=true;
                break;
            case 'oauthcinfo':
                $helper->oauthConsumerInfo($this->_outargs);
                $handled=true;
                break;
            case 'oauthconfirm':
                if ($this->_outargs) {
                    $helper->oauthConfirm($this->_outargs);
                    $handled=true;
                }
                break;
            case 'oauthaddconsumer':
                $helper->oauthAddConsumer($this->_outargs);
                $handled=true;
                break;
            case 'oauthlist':
                $helper->oauthTokenList($this->_outargs);
                $handled=true;
                break;
            default:
                break;
        }

        if ($handled) {
            $this->_debug('handled output');
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
    private function _log ($m = null){
        $OAlog= false; //XXX
        $OAlogdb= '/tmp/oAuth.log';
        $dbh = dba_popen($OAlogfile, 'c', 'inifile');
        if (! isset($OAlog) || $OAlog === false) return;
        $data = array (
            'REMOTE_USER'           => $_SERVER['REMOTE_USER'],
            'HTTP_USER_AGENT'       => $_SERVER['HTTP_USER_AGENT'],
            'REMOTE_ADDR'           => $_SERVER['REMOTE_ADDR'],
            'REMOTE_PORT'           => $_SERVER['REMOTE_PORT'],
            'HTTP_X_REAL_IP'        => $_SERVER['HTTP_X_REAL_IP'],
            'HTTP_X_FORWARDED_FOR'  => $_SERVER['HTTP_X_FORWARDED_FOR'],
            'HTTP_COOKIE'           => $_SERVER['HTTP_COOKIE'],
            'REQUEST_METHOD'        => $_SERVER['REQUEST_METHOD'],
            'REQUEST_URI'           => $_SERVER['REQUEST_URI'],
            'QUERY_STRING'          => $_SERVER['QUERY_STRING'],
            'REQUEST_TIME'          => $_SERVER['REQUEST_TIME'],
            'GET'       => $_GET,
            'POST'      => $_POST,
            'REQUEST'   => $_REQUEST,
            'msg'       => $m
        );
        if (!$dbh ||
            !dba_insert("log_$token", serialize($data), $dbh)) {
            header("HTTP/1.1 500 Internal Server Error");
            echo 'Cannot write to log: ' . $OAlogdb;
            return;
        }
        dba_close($this->dbh);
    } 
    /*}}}*/


    /*{{{*/
    private function _debug ($m = null){
        $OAdebug= true; //XXX
        $OAlogfile= '/tmp/oAuth.debug';
        if (! isset($OAdebug) || $OAdebug === false) return;

        if (! is_writable(dirname($OAlogfile)) &! is_writable($OAlogfile)){
            header("HTTP/1.1 500 Internal Server Error");
            echo 'Cannot write to debug log: ' . $OAlogfile;
            return;
        }
        $vhost=DOKU_URL;
        error_log($vhost.' '.date("c ").$m."\n", 3, $OAlogfile);
    } 
    /*}}}*/

}
//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
