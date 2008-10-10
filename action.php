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

    function handle_act_authhook(&$event, $param){
        if (is_array($_REQUEST['do']) && !empty($_REQUEST['do']['oauth'])) return; // skip requests to oauth-API
        if (!empty($_REQUEST['oauth_signature'])) {
            require_once("dokuoauth.php");
            $user='';
            // verify signature - check consumer and access token
            try {
                $req = OAuthRequest::from_request();

                /// temp. workaround 
                /// until OAuth.php fixes URL-parameter arrays alike do['oauth']=token..
                if ($_REQUEST['do']=="requesttoken") {
                    $token = $doku_server->fetch_request_token($req);
                    print $token;
                    exit(0);
                } else if ($_REQUEST['do']=="accesstoken") {
                    $token = $doku_server->fetch_access_token($req);
                    print $token;
                    exit(0);
                } else
                /// end workaround

                list($consumer, $token) = $doku_server->verify_request($req);

                #print_r($consumer);  # $consumer['key'] -> consumer-key $consumer['secret'] -> consumer-secret
                #print_r($token); # Access-key&secret A

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

    /**
     *
     */
    function handle_act_preprocess(&$event, $param){
        $handled=false;
        if (!empty($event->data['oauth'])) {
            #echo "hello robin,<br/>\n";
            // interactive oAuth - admin
            require_once("dokuoauth.php");
            try {
                switch (trim($event->data['oauth'])) {
                    case 'token':
                        $this->_debug('token');
                        $handled=true;
                        $req = OAuthRequest::from_request();
                        $token = $doku_server->fetch_request_token($req);
                        print $token;
                        break;
                    case 'access':
                        $this->_debug('access');
                        $handled=true;
                        $req = OAuthRequest::from_request();
                        $token = $doku_server->fetch_access_token($req);
                        print $token;
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
    } /*}}}*/

}
//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
