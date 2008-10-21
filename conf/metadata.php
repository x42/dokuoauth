<?php
/**
 * Metadata for configuration manager plugin
 * Additions for the oauth plugin
 *
 * @author    Robin Gareus <robin@gareus.org>
 */
$meta['enable']           = array('onoff');
$meta['manager_admin']    = array('onoff');
$meta['log_all_requests'] = array('onoff');
$meta['trace_plugin']     = array('onoff');
$meta['disclose_access_token_secret'] = array('onoff');
#$meta['custom_base_url']  = array('string');
$meta['consumeradd']      = array('multichoice', '_choices' => array('anyone','users','admins'));
$meta['consumerdel']      = array('multichoice', '_choices' => array('anyone','users','admins'));

//Setup VIM: ex: et ts=2 enc=utf-8 :
