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
            'name'   => 'oauthLogon',
            'desc'   => 'very similar to logon page',
            'params' => array('secpass' => 'string', 'opt' => 'array'),
            'return' => array('success' => 'boolen'),
        );$result[] = array(
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
    public function oauthLogon($secpass, $opt) {
        $this->printHeader();
        if(function_exists('html_msgarea')){
            html_msgarea();
        }
  //    include(template('main.php'));
        $this->printForm($secpass, $opt);
        $this->printFooter();
        exit;
    }

    /**
     *
     */
    public function oauthConfirm($secpass, $opt) {
        $this->printHeader();
        if(function_exists('html_msgarea')){
            html_msgarea();
        }
  //    include(template('main.php'));
        $this->printConfirm($secpass, $opt);
        $this->printFooter();
        exit;
    }

    /**
     *
     */
    private function printForm($secpass, $opt) {
        global $lang;
        global $conf;
    #   global $ID;
        global $auth;

        print p_locale_xhtml('login');
        print '<h3>OAuth</h3>'.NL;
        print '<div class="centeralign">'.NL;
        $form = new Doku_Form('dw__oauth');
        $form->startFieldset($lang['btn_login']);
    #   $form->addHidden('id', $ID);
        $form->addHidden('do[oauth]', 'resume');
        $form->addHidden('dwoauthnonce', $secpass);
        $form->addElement(form_makeTextField('u', $_REQUEST['u'], $lang['user'], 'focus__this', 'block'));
        $form->addElement(form_makePasswordField('p', $lang['pass'], '', 'block'));
    #   $form->addElement(form_makeCheckboxField('r', '1', $lang['remember'], 'remember__me', 'simple'));
        $form->addElement(form_makeButton('submit', '', $lang['btn_login']));
        $form->endFieldset();
        html_form('login', $form);
    }
    /**
     *
     */
    private function printConfirm($secpass, $opt) {
        global $lang;
        global $conf;
    #   global $ID;
        global $auth;

        print p_locale_xhtml('login');
        print '<h3>OAuth - Confirm</h3>'.NL;
        print '<div class="centeralign">'.NL;
        $form = new Doku_Form('dw__oauth');
        $form->startFieldset($lang['btn_login']);
    #   $form->addHidden('id', $ID);
        $form->addHidden('do[oauth]', 'resume');
        $form->addHidden('dwoauthnonce', $secpass);
        $form->addElement(form_makeTextField('u', $_REQUEST['u'], $lang['user'], 'focus__this', 'block'));
        $form->addElement(form_makePasswordField('p', $lang['pass'], '', 'block'));
    #   $form->addElement(form_makeCheckboxField('r', '1', $lang['remember'], 'remember__me', 'simple'));
        $form->addElement(form_makeButton('submit', '', $lang['btn_login']));
        $form->endFieldset();
        html_form('login', $form);
    }
/*
    private function printFormXXX($data, $options, $whatever = NULL) {
        echo '<h3>Dokuwiki - oauth</h3>'."\n";
        echo '<form name="dwoauth" method="post" accept-charset="utf-8" action="'.$data['baseurl'].'">'."\n";
        echo '<fieldset style="width:85%; text-align:left;">'."\n";
        echo '<p><label>Id:</label><br/><input name="id" id="i_id" size="60" value="'.$val.'"/>'; 
        echo '</p>'."\n";

        echo '<p><label>Edit Summary:</label><br/><input name="summary" size="60" value="created: '.htmlentities($data['title']).'"/></p>';
        echo "\n";
        echo '<p>';
        # TODO: add oauth request params here
        echo '<input type="hidden" name="style" value="nomenu"/>';
        echo '<input class="button" type="submit" title="Go" value="authorize" name="do[oauth]"/>';
        echo '&nbsp;|&nbsp;<button class="button" onclick="window.close()">Cancel</button>';
        #echo '&nbsp;<a href="javascript:window.close()">Abort</a>';
        echo '</p>'."\n";
        echo '</fieldset>';
        echo '</form>';
    }
*/
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
   *  - TODO this should use the dokuwiki template header.
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
