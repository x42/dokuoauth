<?php
require_once("OAuth.php");
require_once("OAuth_DokuServer.php");

$doku_server = new DokuOAuthServer(new DokuOAuthDataStore(DOKU_CONF.'oauth.inidb'));
#$doku_server = new DokuOAuthServer(new TestOAuthDataStore());

$doku_server->add_signature_method(new OAuthSignatureMethod_HMAC_SHA1());
#$doku_server->add_signature_method(new OAuthSignatureMethod_PLAINTEXT());
#$doku_server->add_signature_method(new DokuOAuthSignatureMethod_RSA_SHA1());

//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
