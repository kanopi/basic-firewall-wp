<?php
/**
 * Bootstrap for the WordPress-backed suite.
 *
 * Loads the real WordPress rather than the wordpress-develop test suite. The
 * behaviours being pinned here -- what reaches the compiled file, what an export
 * strips, what an import refuses to blank -- depend on the Options API, $wpdb
 * and the real filter chain, and a mocked WordPress would be pinning the mock.
 *
 * Run inside the container:
 *
 *     ddev exec -d /var/www/html/web/wp-content/plugins/basic-firewall \
 *         vendor/bin/phpunit --testsuite integration
 *
 * Or, where the plugin is not physically inside a site, point it at one:
 *
 *     BASIC_FIREWALL_WP_ROOT=/tmp/wp vendor/bin/phpunit --testsuite integration
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

require_once __DIR__ . '/../vendor/autoload.php';

$basic_firewall_wp_load = null;

/*
 * Walking up from __DIR__ only finds the site when the plugin physically lives
 * inside it. CI symlinks the checkout into a throwaway WordPress, and PHP
 * resolves __DIR__ through the symlink to the checkout, which is nowhere near a
 * wp-load.php. So an explicit root wins when one is given.
 */
$basic_firewall_wp_root = getenv( 'BASIC_FIREWALL_WP_ROOT' );

$basic_firewall_candidates = false === $basic_firewall_wp_root || '' === $basic_firewall_wp_root
	? array( dirname( __DIR__, 4 ), dirname( __DIR__, 5 ) )
	: array( rtrim( $basic_firewall_wp_root, '/' ) );

foreach ( $basic_firewall_candidates as $candidate ) {
	if ( is_readable( $candidate . '/wp-load.php' ) ) {
		$basic_firewall_wp_load = $candidate . '/wp-load.php';
		break;
	}
}

if ( null === $basic_firewall_wp_load ) {
	// phpcs:ignore WordPress.WP.AlternativeFunctions -- a CLI test bootstrap; WordPress is what we failed to find.
	fwrite( STDERR, "Could not locate wp-load.php. Run this suite from inside the site, or set BASIC_FIREWALL_WP_ROOT to the WordPress root.\n" );
	exit( 1 );
}

// The firewall must not evaluate the test runner's own "request".
if ( ! defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
	define( 'BASIC_FIREWALL_EVALUATED', true );
}

require_once $basic_firewall_wp_load;
