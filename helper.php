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
            'desc'   => 'very similar to logon page',
            'params' => array('secpass' => 'string', 'opt' => 'array'),
            'return' => array('success' => 'boolen'),
        );
        return $result;
    }

    /**
     *
     */
    public function oauthConfirm($secpass, $opt) {
        $this->printHeader();
        if(function_exists('html_msgarea')){
            html_msgarea();
        }
        $this->printConfirm($secpass, $opt);
        $this->printFooter();
        exit;
    }

    /**
     *
     */
    private function printConfirm($secpass, $opt) {
        global $lang;
        global $conf;
        global $auth;

        print '<h1>OAuth - Authorize Token</h1>'.NL;
        print '<div class="centeralign">'.NL;
        $form = new Doku_Form('dw__oauth');
        $form->startFieldset('Authorize Token');
    #   $form->addHidden('id', $ID);
        $form->addHidden('dwoauthnonce', $secpass);
        $form->addElement('<div class="leftalign"><ul>');
        $form->addElement('<li>Consumer-Key:'.$opt['consumer_key'].'</li>');
        $form->addElement('<li>Token-Key:'.$opt['token_key'].'</li>');
        $form->addElement('<li>Callback URL:'.$opt['callback_url'].'</li>');
        $form->addElement('</ul></div>');
        $form->addElement(form_makeCheckboxField('userconfirmed', '1', 'allow request', 'allow_this', 'simple'));
        $form->addElement(form_makeCheckboxField('trustconsumer', '1', 'always trust this consumer from now on', 'remember__me', 'simple'));
        $form->addElement(form_makeButton('submit', 'oauth', 'resume', array('title' => 'authorize')));
    #   $form->addElement(form_makeButton('submit', '', 'cancel'));
        $form->addElement(form_makeButton('submit', 'oauth', 'cancel'));
        $form->endFieldset();

        // TODO: change-user/re-login button.. (go to logout, keep special $ID='OAUTHPLUGIN:'.$secpass
        html_form('confirm', $form);
    }

    /**
     *
     */
    private function printFooter() { ?>
</div>
</body>
</html>
<?php 
    }

  /**
   *  FIXME this should use the dokuwiki template
   */
    private function printHeader() {
        global $conf;
?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" >
<head>
<title>Dokuwiki OAuth</title>
<link rel="stylesheet" media="all" type="text/css" href="<?php echo DOKU_BASE?>lib/exe/css.php?t=<?php echo $conf['template']?>" />
<link rel="stylesheet" media="screen" type="text/css" href="<?php echo DOKU_BASE?>lib/exe/css.php?s=all&t=<?php echo $conf['template']?>" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<link rel="shortcut icon" href="<?php echo DOKU_TPL?>images/favicon.ico" />
</head>
<body>
<div class="dokuwiki" style="border:0px;">
<?php 
    }

}

//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
