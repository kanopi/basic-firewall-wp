<?php
/**
 * Plugin Name:       Basic Firewall
 * Plugin URI:        https://github.com/kanopi/basic-firewall-wp
 * Description:       Evaluates every request against a set of rules and allows, challenges or blocks it, as early in the request as WordPress can act.
 * Version:           1.0.0
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Kanopi Studios
 * Author URI:        https://kanopi.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       basic-firewall
 * Domain Path:       /languages
 * Network:           false
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * DELIBERATE: this file is written in PHP 5.2-compatible syntax and nothing
 * else. No type declarations, no short array syntax, no null coalescing, no
 * namespaces.
 *
 * The reason is the guard below. A plugin that declares "Requires PHP: 8.1" and
 * then fatals on PHP 7.4 has told the truth in its header and lied in practice,
 * because WordPress only enforces that header on installs performed through the
 * plugin installer -- an upload, a `wp plugin activate`, or a file copied into
 * place all reach this file directly. To report the problem we have to survive
 * being parsed by the very version we are rejecting, and PHP parses an entire
 * file before executing any of it.
 *
 * So: everything modern lives behind basic_firewall_boot(), in files that are
 * only ever require()d once the version check has passed.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Guarded because the mu-plugin loader requires this file before WordPress
 * would have, to run the firewall earlier than the plugin loader does.
 * include_once makes WordPress's own later include a no-op, but a stray
 * require from anywhere else must not produce a wall of redefinition notices.
 */
if ( defined( 'BASIC_FIREWALL_VERSION' ) ) {
	return;
}

define( 'BASIC_FIREWALL_VERSION', '1.0.0' );
define( 'BASIC_FIREWALL_MIN_PHP', '8.1' );
define( 'BASIC_FIREWALL_FILE', __FILE__ );
define( 'BASIC_FIREWALL_DIR', plugin_dir_path( __FILE__ ) );
define( 'BASIC_FIREWALL_URL', plugin_dir_url( __FILE__ ) );

/**
 * Whether the running PHP version can load the plugin.
 *
 * @return bool
 */
function basic_firewall_php_is_supported() {
	return version_compare( PHP_VERSION, BASIC_FIREWALL_MIN_PHP, '>=' );
}

/**
 * Deactivate, and say why.
 *
 * Deactivating is the honest response rather than lying dormant: a security
 * plugin that is listed as active while evaluating nothing is worse than one
 * that is plainly off.
 *
 * @return void
 */
function basic_firewall_halt_unsupported_php() {
	if ( ! function_exists( 'deactivate_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	deactivate_plugins( plugin_basename( BASIC_FIREWALL_FILE ), true );

	/*
	 * Suppress the "Plugin activated" notice, which would otherwise contradict
	 * us. This reads no value and processes no form data -- it removes a flag
	 * WordPress itself set moments ago -- so there is nothing to verify a nonce
	 * against.
	 */
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	if ( isset( $_GET['activate'] ) ) {
		unset( $_GET['activate'] );
	}

	add_action( 'admin_notices', 'basic_firewall_unsupported_php_notice' );
}

/**
 * The notice explaining the deactivation.
 *
 * @return void
 */
function basic_firewall_unsupported_php_notice() {
	echo '<div class="notice notice-error"><p><strong>';
	echo esc_html__( 'Basic Firewall has been deactivated.', 'basic-firewall' );
	echo '</strong> ';

	printf(
		/* translators: 1: required PHP version, 2: PHP version currently running. */
		esc_html__( 'It requires PHP %1$s or later, and this site is running PHP %2$s. The firewall was not started, so no traffic is being evaluated.', 'basic-firewall' ),
		esc_html( BASIC_FIREWALL_MIN_PHP ),
		esc_html( PHP_VERSION )
	);

	echo ' ';
	echo esc_html__( 'Ask your host to upgrade PHP, then activate the plugin again.', 'basic-firewall' );
	echo '</p></div>';
}

/**
 * Load the plugin proper.
 *
 * Everything below the version gate is PHP 8.1+.
 *
 * @return void
 */
function basic_firewall_boot() {
	if ( ! basic_firewall_php_is_supported() ) {
		add_action( 'admin_init', 'basic_firewall_halt_unsupported_php' );
		return;
	}

	require_once BASIC_FIREWALL_DIR . 'loader.php';
}

/*
 * Activation is registered outside the gate so that activating on unsupported
 * PHP fails loudly and immediately rather than half-installing.
 */
register_activation_hook( __FILE__, 'basic_firewall_activate' );
register_deactivation_hook( __FILE__, 'basic_firewall_deactivate' );

/**
 * Activation entry point.
 *
 * @return void
 */
function basic_firewall_activate() {
	if ( ! basic_firewall_php_is_supported() ) {
		// wp_die() rather than a notice: activation must not appear to succeed.
		wp_die(
			esc_html(
				sprintf(
					/* translators: 1: required PHP version, 2: PHP version currently running. */
					__( 'Basic Firewall requires PHP %1$s or later. This site is running PHP %2$s.', 'basic-firewall' ),
					BASIC_FIREWALL_MIN_PHP,
					PHP_VERSION
				)
			),
			esc_html__( 'Cannot activate Basic Firewall', 'basic-firewall' ),
			array( 'back_link' => true )
		);
	}

	require_once BASIC_FIREWALL_DIR . 'loader.php';
	// String-referenced so this file still parses on PHP without namespace support.
	call_user_func( array( 'Kanopi\\BasicFirewall\\Install\\Activator', 'activate' ) );
}

/**
 * Deactivation entry point.
 *
 * @return void
 */
function basic_firewall_deactivate() {
	if ( ! basic_firewall_php_is_supported() ) {
		return;
	}

	require_once BASIC_FIREWALL_DIR . 'loader.php';
	call_user_func( array( 'Kanopi\\BasicFirewall\\Install\\Activator', 'deactivate' ) );
}

basic_firewall_boot();
