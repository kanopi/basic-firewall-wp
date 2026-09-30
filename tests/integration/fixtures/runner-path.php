<?php
/**
 * A site evaluated by the runner alone, for BlockModeNoticeTest.
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * Served by PHP's built-in web server, as a router: every request runs this,
 * then real WordPress, which the mu-plugin loader evaluates at
 * `muplugins_loaded`.
 *
 * The site's wp-config.php requires the real bootstrap.php (the DDEV site's
 * does). Declaring basic_firewall_evaluate() first makes it skip the real
 * one -- its declarations are guarded -- and this one evaluates nothing and
 * leaves BASIC_FIREWALL_EVALUATED undefined, so the request is the runner's:
 * the path a site without the wp-config.php snippet is on.
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- a test fixture, before WordPress.

/*
 * The site's own host and path: a network answers only the domain it was
 * installed on, and the server is listening somewhere else. The request
 * path is kept as sent, under the site's path.
 */
if ( '' !== (string) getenv( 'BFW_RUNNER_HOST' ) ) {
	$_SERVER['HTTP_HOST']   = (string) getenv( 'BFW_RUNNER_HOST' );
	$_SERVER['SERVER_NAME'] = (string) preg_replace( '/:\d+$/', '', (string) getenv( 'BFW_RUNNER_HOST' ) );
}

$_SERVER['REQUEST_URI'] = rtrim( (string) getenv( 'BFW_RUNNER_PATH' ), '/' ) . (string) ( $_SERVER['REQUEST_URI'] ?? '/' );

/**
 * An early path that is not there.
 *
 * @param array<string, mixed> $options Ignored.
 *
 * @return bool Always true: the request goes on to the runner.
 */
function basic_firewall_evaluate( array $options = array() ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- the real bootstrap's signature.
	return true;
}

require (string) getenv( 'BFW_RUNNER_WP_LOAD' );

echo 'SERVED BY WORDPRESS';
