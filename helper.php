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
            'params' => array('id' => 'string', 'page' => 'array', 'opt' => 'array'),
            'return' => array('success' => 'boolen'),
        );
        return $result;
    }


    /**
     *
     */
    public function oauthLogon($id, $page, $opt) {
        global $conf;
        global $ACT;
        nice_die("you'll need to log in.");
    }

    /**
     *
     */
    private function printForm($data, $options, $alltags = NULL) {
        echo '<h3>Dokuwiki - oauth</h3>';
        echo '<form name="dwoauth" method="post" accept-charset="utf-8" action="'.$data['baseurl'].'">';
        echo '<fieldset style="width:85%; text-align:left;">';
        echo '<p><label>Id:</label><br/><input name="id" id="i_id" size="60" value="'.$val.'"/>'; 
        echo '</p>'."\n";

        echo '<p><label>Edit Summary:</label><br/><input name="summary" size="60" value="created: '.htmlentities($data['title']).'"/></p>';
        echo '<p>';
        echo '<input type="hidden" name="style" value="nomenu"/>';
        echo '<input class="button" type="submit" title="Preview" value="Preview" name="do[preview]"/>';
        echo '&nbsp;|&nbsp;<button class="button" onclick="window.close()">Cancel</button>';
        #echo '&nbsp;<a href="javascript:window.close()">Abort</a>';
        echo '</p>';
        echo '</fieldset>';
        echo '</form>';
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
}

//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
