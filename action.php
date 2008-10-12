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

        /// temp. workaround 
        /// until OAuth.php fixes request-parameter arrays alike do['oauth']=token..
        if (in_array($_REQUEST['do'], array("requesttoken", "accesstoken"))){
            $data=array('oauth' => $_REQUEST['do']);
            #$this->_debug("workaround do[oauth]: ".print_r($event,true));
            $ev=new Doku_Event("OAUTH_ACT_PREPROCESS", $data);
            $this->handle_act_preprocess($ev, NULL);
            unset($ev);
            exit(0);
        }
        /// end workaround

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
            if (!is_array($USERINFO)) { // XXX
                $_SERVER['REMOTE_USER'] = "";
                $this->_debug('oAuth: could not find user: '.$user);
            } 
            else $this->_debug('oAuth: set-user: '.$user);
        }
    }


# FLOW;
# - [admin,user,auto] add consumer 
# - get request-token
#    [auto] if consumer is suid (no-browser - return token or redirect to consumer)
#    [auto] if user is logged-on and has whitelisted the consumer -> redirect to consumer
#    [user] if user is logged-on -> as for confirmation  -> redirect to consumer
#    [user] log-in (remember consumer) -> try-again to check/ask for confirmation -> redirect to consumer
#
# - [auto] get access-token (done)
#    check if request token is valid for this consumer and has a dokuwiki user mapped to it..  
#
    /**
     *
     */
    function handle_act_preprocess(&$event, $param){
        $handled=false;
        if (!empty($event->data['oauth'])) {
            // interactive oAuth - admin
            require_once("dokuoauth.php");
            try {
                switch (trim($event->data['oauth'])) {
                    case 'accesstoken':
                        $this->_debug('access');
                        $handled=true;
                        $req = OAuthRequest::from_request();
                        $token = $doku_server->fetch_access_token($req);
                        # DokuOAuthDataStore: 
                        #  - tests if given request-token has been (authorized by|mapped to) a user 
                        #  - if not user found: `fetch_access_token()` returns NULL!
                        #     else the request-token is exchanged for an access-token, retraining the user mapping
                        print $token;
                        break;
                    case 'authorize':
                        $this->_debug('authorize');
                        $req = OAuthRequest::from_request();
                        $op=$req->get_parameters();
                        $consumer_key=$op['oauth_consumer_key'];

                        $user = $this->check_consumer_acl($doku_server, $consumer_key);

                        #create here and save during log-in, whitelist-check, confirm.. ?!
                        #$token = $doku_server->fetch_request_token($req);

                        if (empty($user)) {
                          # TODO password-log-in and return here (save $req) 
                          nice_die("you'll need to log in.");
                          break;
                        }
                    case 'requesttoken': # test only !! -> use "authorize"
                        $this->_debug('token');
                        $req = OAuthRequest::from_request();
                        if (empty($user)) $user='rgareus'; // XXX test
                        $handled=true;
                    case 'confirm':
                        if (!isset($req)) break; // XXX - we get here from 'authorize' , $user and $req are set
                        $op=$req->get_parameters();
                        $consumer_key=$op['oauth_consumer_key'];

                        $token = $doku_server->fetch_request_token($req); /// XXX get from above ?!

                        if (empty($user) || !$this->check_consumer_confirm($doku_server, $user, $consumer_key, $token)) {
                          # TODO ask for confirmation and return here (save $req);
                          nice_die("you'll need to confirm this consumer request.");
                          break;
                        }
                        $doku_server->map_user($user,$consumer_key, $token->key);

                        // redirect back to $consumer->callback_url add $request-token.
                        $consumer = $doku_server->get_consumer_by_key($consumer_key);
                        if (!empty($consumer->callback_url)) {
                            $this->redirect($consumer->callback_url, array(
                                    'oauth_token'=>rawurlencode($token->key),
                                    'oauth_token_secret'=>rawurlencode($token->secret)
                                    # TODO: include xoauth parameters
                                    ));
                        } else  {
                            print $token;
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
            $event->stopPropagation();
            $event->preventDefault();
        }
    }
    private function check_consumer_acl($doku_server, $consumer_key) {/*{{{*/
        $aclimit = $doku_server->get_consumer_acl($consumer_key);
        $user=NULL;
        if (is_array($acllimit) && !empty($aclimit['suid'])) {
           $user = $aclimit['suid'];
           return $user;
        } 
        if ($_SERVER['REMOTE_USER']) {
            $user=$_SERVER['REMOTE_USER'];
        } else if (auth_login("","",false,true)) {
        # auth_login($_REQUEST['u'],$_REQUEST['p'],$_REQUEST['r'],false,true); # workaround for workaround above ;)
            global $USERINFO;
            $user=$_SERVER['REMOTE_USER'];
        }
        // TODO : check acllimit array..
        // check group, not is_admin, etc.
        #if (!in_array($user, $aclimit['users'])) $user=NULL;

        return $user;
    }/*}}}*/

    private function check_consumer_confirm($doku_server, $user, $consumer_key, $request_token) {/*{{{*/
        $aclimit = $doku_server->get_consumer_acl($consumer_key);
        if (is_array($acllimit) && !empty($aclimit['suid'])) return true;

        // TODO: check database ... for user <> consumer  user-whitelist (auto-confirm)
        // TODO: check database ... for user <> consumer  user-confirmed
        # can eventually use 
        #   $doku_server->map_user($user,$consumer_key, $token->key);
        # and get_dokuwiki_user(..) with dokuwiki-POST..
        return true; /// XXX
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
