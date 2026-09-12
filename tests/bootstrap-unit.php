<?php
/**
 * Bootstrap for the pure-unit suite.
 *
 * Deliberately does not load WordPress. Everything in tests/unit must be
 * testable without it -- that is what makes the suite fast enough to run on
 * every save, and it is a design constraint on the code as much as on the
 * tests: a class that cannot be constructed without WordPress is a class that
 * has WordPress mixed into logic that does not need it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

require_once __DIR__ . '/../vendor/autoload.php';

if ( ! defined( 'BASIC_FIREWALL_DIR' ) ) {
	define( 'BASIC_FIREWALL_DIR', dirname( __DIR__ ) . '/' );
}

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', dirname( __DIR__ ) . '/' );
}
