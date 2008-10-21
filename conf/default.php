<?php
/**
 * Options for the oauth Plugin
 */
$conf['enable']           = true; // en/disable authentication of oauth signed requests, admin is indep.
$conf['manager_admin']    = false; // allow managers to administrate ALL oauth-tokens.
$conf['custom_base_url']  = ''; // allow to override oauth-endpoint URL - NYI -> helper.php
$conf['log_all_requests'] = false; // oAuth debug log - don't use
$conf['trace_plugin']     = false; // debug trace dokuwiki flow in oauth plugin
$conf['disclose_access_token_secret'] = true;
$conf['consumeradd']      = 'anyone'; // who may add consumers
$conf['consumerdel']      = 'users'; // who may delete consumers added by 'anyone'

//Setup VIM: ex: et ts=2 enc=utf-8 :
