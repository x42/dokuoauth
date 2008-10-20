<?php
/**
 * oauth plugin helper functions
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Robin Gareus <robin@gareus.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class helper_plugin_oauth extends DokuWiki_Plugin {

    /**
     * Constructor
     */
    function helper_plugin_oauth() {
        ;
    }

    # THIS IS VERY MUCH WORK IN PROGRESS...

    // TODO:
    #  - general feedback page, error, info
    #  - Consumer Admin
    #    - add/generate consumer key&pass,url (later: disco)
    #    - list consumer  (key, admin: key&pass)
    #    - edit consuer settings, callback-URL?
    #    - delete consumer, blacklist consumer: users=array();
    #  - Token Admin    
    #    - list access|request token 
    #      - per user
    #      - per consumer
    #    - revoke access tokens 

    # - prepare for time-window, validity of token and/or consumer.
    #   or revoke token after N requests

    # - prepare for user/group-admin (for consumers)

    /**
     * return some info
     */
    function getInfo(){
        return array(
            'author' => 'Robin Gareus',
            'email'  => 'robin@gareus.org',
            'date'   => '2008-10-12',
            'name'   => 'oauth',
            'desc'   => 'Authorize User requests by oAuth',
            'url'    => 'http://mir.dnsalias.com/wiki/dokuoauth',
        );
    }

    /**
     * announce public functions the dokuwiki way.
     */
    function getMethods(){
        $result = array();
        $result[] = array(
            'name'   => 'oauthConfirm',
            'desc'   => 'ask user to authorize token',
            'params' => array('opt' => 'array'),
            'return' => array('success' => 'boolen'),
        );
        $result[] = array(
            'name'   => 'oauthConsumerInfo',
            'desc'   => 'show consumer info',
            'params' => array('opt' => 'array'),
            'return' => array('success' => 'boolen'),
        );
        return $result;
    }

    /**
     *
     */
    public function oauthConfirm($opt) {
        global $lang;
        global $conf;
        global $auth;

        print '<h1>OAuth - Authorize Token</h1>'.NL;
        print '<div class="leftalign">'.NL;
        print '<p>A Consumer wants to make one or more requests on your behalf which requires your consent.<p>'.NL;
        print '</div>'.NL;
        print '<div class="centeralign">'.NL;
        $form = new Doku_Form('dw__oauth');
        $form->startFieldset('Authorize Request Token');
    #   $form->addHidden('id', $ID);
        $form->addElement('<p>Your Username: '.$_SERVER['REMOTE_USER'].'</p>');
        $form->addHidden('dwoauthnonce', $opt['secpass']);
        $form->addElement('<div class="leftalign"><ul>');
        $form->addElement('<li>Consumer-Key:'.$opt['consumer_key'].'</li>');
        $form->addElement('<li><a href="?do[oauth]=cinfo&dwoauthnonce='.rawurlencode($opt['secpass']).'" alt="consumer info">Consumer Info</a></li>');
        $form->addElement('<li>Token-Key:'.$opt['token_key'].'</li>');
        $form->addElement('<li>Callback URL:'.$opt['callback_url'].'</li>');
        $form->addElement('</ul></div>');
        $form->addElement(form_makeCheckboxField('userconfirmed', '1', 'allow request', 'allow_this', 'simple'));
        $form->addElement(form_makeCheckboxField('trustconsumer', '1', 'always trust this consumer from now on', 'remember__me', 'simple'));
        $form->addElement(form_makeButton('submit', 'oauth', 'resume', array('title' => 'authorize')));
    #   $form->addElement(form_makeButton('submit', '', 'cancel'));
        $form->addElement(form_makeButton('submit', 'oauth', 'cancel'));
        $form->endFieldset();

        // TODO: change-user/re-login button.. (go to logout, keep special $ID='OAUTHPLUGIN:'.$opt['secpass']
        html_form('confirm', $form);
        print '</div>'.NL;
        print '<div class="leftalign">'.NL;
        print '<p><b>small print</b></p>'.NL;
        print '<p>At this stage of prototying the dokuwiki OAuth plugin we are not able to assure the Consumer’s true identity.</p>'.NL;
        print '<p>The request token you are about to authorize is valid only once: to get an access-token, the latter can be used to perform (multiple) requests using your account until it expires or you revoke it.<br/>'.NL;
        print 'A consumer may also forget the access-token and come back here every once in a while. Once consumer-verification is implemented and you have validated the consumer-information you may opt in to trust this consumer when you are logged in to dokuwiki to bypass this step by checking the "trust consumer" checkbox.</p>'.NL;
        print '</div>'.NL;
    }

    /**
     *
     */
    public function oauthConsumerInfo($opt) {
        global $lang;
        global $conf;
        global $auth;

        print '<h1>OAuth - Consumer Info</h1>'.NL;
        print '<div class="leftalign">'.NL;
        print '</div>'.NL;
        print '<div class="centeralign">'.NL;
        $form = new Doku_Form('dw__oauth');
        $form->startFieldset('Consumer Info');
        if (!empty($opt['secpass']))
            $form->addHidden('dwoauthnonce', $opt['secpass']);
        $form->addElement('<div class="leftalign"><ul>');
        $form->addElement('<li>Consumer-Key:'.$opt['consumer_key'].'</li>');
        $form->addElement('<li>Consumer-secret:'.$opt['consumer_secret'].'</li>');
        $form->addElement('<li>Callback URL:'.$opt['callback_url'].'</li>');
        $form->addElement('</ul></div>');
        if (!empty($opt['secpass'])) {
            $form->addElement(form_makeButton('submit', 'oauth', 'resume', array('title' => 'authorize')));
            $form->addElement(form_makeButton('submit', 'oauth', 'cancel'));
        } else {
            $form->addHidden('consumer_key', $opt['consumer_key']); 
            $form->addElement(form_makeButton('submit', 'oauth', 'cinfo')); // XXX
        }
        $form->endFieldset();

        // TODO: change-user/re-login button.. (go to logout, keep special $ID='OAUTHPLUGIN:'.$opt['secpass']
        html_form('info', $form);
        print '</div>'.NL;
    }

}

//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
