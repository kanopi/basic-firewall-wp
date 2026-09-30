<?php
/**
 * Stands in for wp-config.php, for EarlyPathExceptionModeTest and DirectFileRequestTest.
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * Served by PHP's built-in web server, so the bootstrap runs the way it does
 * from a real wp-config.php: first, under a web SAPI, before any WordPress
 * exists. A web SAPI matters -- under the CLI the library waves every request
 * through in every mode but `exception`, so a CLI test of `block` mode would be
 * asserting the bypass.
 *
 * Everything after the call stands in for WordPress loading. Its marker
 * reaching a response therefore means the firewall let the request through,
 * which is the fail-open this fixture exists to catch.
 */

$basic_firewall_plugin = (string) getenv( 'BFW_EARLY_PLUGIN_PATH' );

/*
 * A network's wp-config.php defines these above the snippet. A request header
 * stands in for that here, so one server can play both kinds of site.
 */
if ( isset( $_SERVER['HTTP_X_BFW_TEST_NETWORK'] ) ) {
	define( 'MULTISITE', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- WordPress's own constant, as a network's wp-config.php defines it.
	define( 'SUBDOMAIN_INSTALL', false ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals -- as above.
}

/*
 * Where the Composer autoloader is, as a site would say it. A request header
 * picks the scenario so one server can play every kind of install:
 *
 * - `X-Bfw-Test-Plugin: bare` runs the plugin from a copy with no vendor/,
 *   as a site-level Composer install has, so its own autoloader is not there
 *   to win.
 * - `X-Bfw-Test-Autoloader` names the site's autoloader through the option,
 *   the constant, both, a path that does not exist, or by having required it
 *   above the snippet -- the way a site loads its vendor-dir itself.
 *
 * The site autoloader is a stand-in that records being loaded, then loads
 * the real one: which file won is what the scoped-first test asserts.
 */
$basic_firewall_bootstrap = array(
	'private_path' => (string) getenv( 'BFW_EARLY_PRIVATE_PATH' ),
	'plugin_path'  => $basic_firewall_plugin,
);

if ( 'bare' === ( $_SERVER['HTTP_X_BFW_TEST_PLUGIN'] ?? '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against a literal, in a test fixture with no WordPress to unslash with.
	$basic_firewall_bootstrap['plugin_path'] = (string) getenv( 'BFW_EARLY_BARE_PLUGIN_PATH' );
}

$basic_firewall_custom  = (string) getenv( 'BFW_EARLY_CUSTOM_AUTOLOADER' );
$basic_firewall_missing = dirname( $basic_firewall_custom ) . '/not-here/autoload.php';

switch ( $_SERVER['HTTP_X_BFW_TEST_AUTOLOADER'] ?? '' ) {
	case 'option':
		$basic_firewall_bootstrap['autoloader'] = $basic_firewall_custom;
		break;
	case 'constant':
		define( 'BASIC_FIREWALL_AUTOLOADER', $basic_firewall_custom );
		break;
	case 'both':
		// The option is the more local of the two, and wins.
		define( 'BASIC_FIREWALL_AUTOLOADER', $basic_firewall_missing );
		$basic_firewall_bootstrap['autoloader'] = $basic_firewall_custom;
		break;
	case 'missing':
		$basic_firewall_bootstrap['autoloader'] = $basic_firewall_missing;
		break;
	case 'missing-constant':
		define( 'BASIC_FIREWALL_AUTOLOADER', $basic_firewall_missing );
		break;
	case 'preloaded':
		require_once $basic_firewall_custom;
		break;
}

/*
 * The PHP error log, somewhere a test can read it: the built-in server's own
 * stderr goes nowhere.
 */
if ( '' !== (string) getenv( 'BFW_EARLY_ERROR_LOG' ) ) {
	ini_set( 'error_log', (string) getenv( 'BFW_EARLY_ERROR_LOG' ) ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- a test fixture pointing the log at a file the test reads.
}

// BASIC_FIREWALL_DEBUG, as a site would define it above the snippet.
if ( isset( $_SERVER['HTTP_X_BFW_TEST_DEBUG'] ) ) {
	define( 'BASIC_FIREWALL_DEBUG', true );
}

/*
 * A firewall that fails partway through evaluating, with something that is
 * not a verdict: see fake-request-factory.php.
 */
if ( isset( $_SERVER['HTTP_X_BFW_TEST_THROW'] ) ) {
	require_once __DIR__ . '/fake-request-factory.php';
}

/*
 * A responder that fails to answer, standing in for the real one: see
 * fake-responder.php. And a plugin copy with no responder at all.
 */
if ( in_array( $_SERVER['HTTP_X_BFW_TEST_RESPONDER'] ?? '', array( 'throws', 'returns' ), true ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against literals, in a test fixture.
	require_once __DIR__ . '/fake-responder.php';
}

if ( 'no-responder' === ( $_SERVER['HTTP_X_BFW_TEST_PLUGIN'] ?? '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against a literal, in a test fixture.
	$basic_firewall_bootstrap['plugin_path'] = (string) getenv( 'BFW_EARLY_NO_RESPONDER_PLUGIN_PATH' );
}

require_once $basic_firewall_plugin . '/bootstrap.php';

if ( isset( $_SERVER['HTTP_X_BFW_TEST_FOREIGN_VERDICT'] ) ) {
	/*
	 * A challenge from the other library copy, handed straight to the
	 * bootstrap's answer the way a catch around evaluate() would hand it.
	 */
	require_once __DIR__ . '/foreign-verdict.php';

	basic_firewall_answer_outcome(
		new \Kanopi\BasicFirewall\Vendor\Kanopi\Firewall\Exception\ChallengeRequiredException( 'Challenge required by plugin: foreign' ),
		null,
		basic_firewall_options( $basic_firewall_bootstrap )
	);
} else {
	basic_firewall_evaluate( $basic_firewall_bootstrap );
}

// What the bootstrap left for the runner, for a test to assert on.
header( 'X-Early-Stashed: ' . ( empty( $GLOBALS['basic_firewall_outcome'] ) ? 'no' : 'yes' ) );
header( 'X-Early-Outcome: ' . (string) ( $GLOBALS['basic_firewall_early']['outcome'] ?? 'none' ) );
header( 'X-Early-Reason: ' . (string) ( $GLOBALS['basic_firewall_early']['reason'] ?? 'none' ) );
header( 'X-Early-Evaluated: ' . ( empty( $GLOBALS['basic_firewall_early']['evaluated'] ) ? 'no' : 'yes' ) );
header( 'X-Early-Autoloader: ' . (string) ( $GLOBALS['basic_firewall_early']['autoloader']['source'] ?? 'none' ) );
header( 'X-Early-Autoloader-File: ' . (string) ( $GLOBALS['basic_firewall_early']['autoloader']['file'] ?? '' ) );
header( 'X-Early-Autoloader-Named: ' . (string) ( $GLOBALS['basic_firewall_early']['autoloader']['named'] ?? '' ) );
// PHP_SELF as WordPress will read it, to prove the firewall left it alone:
// WordPress sets $pagenow from it.
header( 'X-Early-Php-Self: ' . (string) ( $_SERVER['PHP_SELF'] ?? '' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- echoed to a test, in a fixture with no WordPress to sanitize with.
header( 'X-Early-Custom-Loaded: ' . ( empty( $GLOBALS['basic_firewall_test_custom_autoloader'] ) ? 'no' : 'yes' ) );

echo 'SERVED BY WORDPRESS';
