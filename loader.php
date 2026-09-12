<?php
/**
 * Resolves how the plugin and the firewall library are autoloaded.
 *
 * Reached only after the PHP version gate in basic-firewall.php, so PHP 8.1+
 * syntax is safe from here down.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( defined( 'BASIC_FIREWALL_LOADED' ) ) {
	return;
}
define( 'BASIC_FIREWALL_LOADED', true );

/*
 * The plugin's own classes, always PSR-4 from src/.
 *
 * Registered by hand rather than through Composer so that the plugin's own code
 * is loadable even when the vendor tree is missing or broken -- which is
 * exactly the situation the Site Health test needs to be able to report on.
 * A firewall that cannot explain why it is not running is worse than one that
 * is not running.
 */
spl_autoload_register(
	static function ( string $class ): void {
		$prefix = 'Kanopi\\BasicFirewall\\';
		$length = strlen( $prefix );

		if ( 0 !== strncmp( $prefix, $class, $length ) ) {
			return;
		}

		$relative = substr( $class, $length );
		$path     = BASIC_FIREWALL_DIR . 'src/' . str_replace( '\\', '/', $relative ) . '.php';

		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
);

Kanopi\BasicFirewall\Library_Loader::boot();
Kanopi\BasicFirewall\Plugin::instance()->register();
