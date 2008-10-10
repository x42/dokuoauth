<?php
require_once("OAuth.php");
require_once("OAuth_DokuServer.php");

#@$domain = $_SERVER['HTTP_HOST'];
#$base = "/oauth/example";
#$base_url = "http://$domain$base";

#$doku_server = new DokuOAuthServer(new DokuOAuthDataStore(DOKU_CONF.'oauth.gdbm'));
#$doku_server = new DokuOAuthServer(new DokuOAuthDataStore());
$doku_server = new DokuOAuthServer(new TestOAuthDataStore());

#$hmac_method = new OAuthSignatureMethod_HMAC_SHA1();
#$plaintext_method = new OAuthSignatureMethod_PLAINTEXT();
#$rsa_method = new DokuOAuthSignatureMethod_RSA_SHA1();
#
#$doku_server->add_signature_method($hmac_method);
#$doku_server->add_signature_method($plaintext_method);
#$doku_server->add_signature_method($rsa_method);
$doku_server->add_signature_method(new OAuthSignatureMethod_HMAC_SHA1());

#$sig_methods = $doku_server->get_signature_methods();

//Setup VIM: ex: et sw=4 ts=4 enc=utf-8 :
