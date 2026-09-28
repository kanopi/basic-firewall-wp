<?php
/**
 * Stands in for wp-config.php, for EarlyPathExceptionModeTest.
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

require_once $basic_firewall_plugin . '/bootstrap.php';

basic_firewall_evaluate(
	array(
		'private_path' => (string) getenv( 'BFW_EARLY_PRIVATE_PATH' ),
		'plugin_path'  => $basic_firewall_plugin,
	)
);

// What the bootstrap left for the runner, for a test to assert on.
header( 'X-Early-Stashed: ' . ( empty( $GLOBALS['basic_firewall_outcome'] ) ? 'no' : 'yes' ) );
header( 'X-Early-Outcome: ' . (string) ( $GLOBALS['basic_firewall_early']['outcome'] ?? 'none' ) );

echo 'SERVED BY WORDPRESS';
