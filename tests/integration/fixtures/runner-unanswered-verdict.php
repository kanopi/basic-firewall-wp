<?php
/**
 * A site whose wp-config.php bootstrap records a verdict and lets the request go on, for RunnerRefusalTest.
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * Served by PHP's built-in web server, as a router: every request runs this,
 * then real WordPress.
 *
 * It stands in for the one case the runner's tripwire exists for (#36): a
 * bootstrap that reached a challenge, redirect or block verdict, recorded it
 * in its report, and returned without answering it or leaving it in the
 * stash for the runner -- an older bootstrap.php still required from
 * wp-config.php, or one that failed open on a verdict (#34). The current
 * bootstrap never does this, so it cannot be made to; this function takes its
 * name instead.
 *
 * Declared before WordPress loads, so a wp-config.php that requires the real
 * bootstrap.php (the DDEV site's does) finds basic_firewall_evaluate()
 * already defined, skips the real one -- its declarations are guarded -- and
 * calls this. Called here as well, for a wp-config.php that does not.
 *
 * `X-Bfw-Test-Verdict` picks the verdict; without it the bootstrap records
 * none, and the request is the control that WordPress serves at all.
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- a test fixture, before WordPress, comparing against literals.

$basic_firewall_test_verdict = (string) ( $_SERVER['HTTP_X_BFW_TEST_VERDICT'] ?? '' );

if ( '' !== (string) getenv( 'BFW_RUNNER_ERROR_LOG' ) ) {
	ini_set( 'error_log', (string) getenv( 'BFW_RUNNER_ERROR_LOG' ) ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- a test fixture pointing the log at a file the test reads.
}

/*
 * The site's own host and path: a network answers only the domain it was
 * installed on, and the server is listening somewhere else.
 */
if ( '' !== (string) getenv( 'BFW_RUNNER_HOST' ) ) {
	$_SERVER['HTTP_HOST']   = (string) getenv( 'BFW_RUNNER_HOST' );
	$_SERVER['SERVER_NAME'] = (string) preg_replace( '/:\d+$/', '', (string) getenv( 'BFW_RUNNER_HOST' ) );
}

$_SERVER['REQUEST_URI'] = rtrim( (string) getenv( 'BFW_RUNNER_PATH' ), '/' ) . '/bfw-runner-refusal';

/**
 * An early path that records a verdict and does not answer it.
 *
 * @param array<string, mixed> $options Ignored.
 *
 * @return bool Always true: the request goes on.
 */
function basic_firewall_evaluate( array $options = array() ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- the real bootstrap's signature.
	$GLOBALS['basic_firewall_early'] = array(
		'called'      => true,
		'credentials' => true,
		'evaluated'   => true,
		'reason'      => null,
		'responder'   => true,
	);

	if ( '' !== $GLOBALS['basic_firewall_test_verdict'] ) {
		$GLOBALS['basic_firewall_early']['outcome'] = $GLOBALS['basic_firewall_test_verdict'];
	}

	if ( ! defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
		define( 'BASIC_FIREWALL_EVALUATED', true );
	}

	return true;
}

basic_firewall_evaluate();

require (string) getenv( 'BFW_RUNNER_WP_LOAD' );

echo 'SERVED BY WORDPRESS';
