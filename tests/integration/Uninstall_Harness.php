<?php
/**
 * Runs the plugin's uninstall against a real site, and puts the site back.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Plugin;

/**
 * Shared by every test that runs uninstall.php.
 *
 * Uninstall deletes the options, the private directory, the mu-plugin loader
 * and the capabilities of the site the suite runs against. Each test that runs
 * it has to leave that site as it found it -- configured and armed -- and two
 * copies of "as it found it" would drift the first time one of them learned
 * about something new to restore.
 */
trait Uninstall_Harness {

	/**
	 * Options this site had before the test.
	 *
	 * @var array<string, mixed>
	 */
	private array $plugin_state = array();

	/**
	 * Snapshot everything the plugin owns in the options table.
	 */
	private function snapshot_plugin_state(): void {
		$this->plugin_state = array();

		foreach ( $this->plugin_option_names() as $name ) {
			$this->plugin_state[ $name ] = get_option( $name, null );
		}
	}

	/**
	 * Put it all back, and leave the site activated.
	 *
	 * "Activated" includes the mu-plugin loader, and that was the one piece
	 * this used to leave behind. `uninstall.php` deletes the loader, so a suite
	 * run ended with the site's earliest evaluation point quietly gone: the
	 * firewall dropped from `muplugins_loaded` to `plugins_loaded`, which still
	 * works and looks identical from the admin screens, so nothing said so. On
	 * a site also running the wp-config.php path it was invisible, because
	 * that path supersedes the loader and Site Health then reports the better
	 * answer.
	 *
	 * A test suite that disarms the firewall it is testing is worse than one
	 * that fails, and this is the second form that took -- the first was the
	 * compiled file, restored here for the same reason.
	 */
	private function restore_plugin_state(): void {
		foreach ( $this->plugin_option_names() as $name ) {
			if ( ! array_key_exists( $name, $this->plugin_state ) ) {
				delete_option( $name );
			}
		}

		foreach ( $this->plugin_state as $name => $value ) {
			if ( null === $value ) {
				delete_option( (string) $name );
			} else {
				update_option( (string) $name, $value, false );
			}
		}

		Plugin::instance()->paths()->reset();
		Plugin::instance()->settings()->flush();
		Capabilities::grant();
		Plugin::instance()->paths()->ensure();
		Plugin::instance()->compiled()->rebuild();
		$this->restore_mu_plugin();
	}

	/**
	 * Reinstate the mu-plugin loader if a test removed it.
	 *
	 * Copied directly rather than by running `Activator::activate()`, which
	 * would write the default settings back over the snapshot that has just
	 * been restored.
	 */
	private function restore_mu_plugin(): void {
		$target = WPMU_PLUGIN_DIR . '/basic-firewall-loader.php';

		if ( file_exists( $target ) ) {
			return;
		}

		$source = dirname( __DIR__, 2 ) . '/mu-plugin/basic-firewall-loader.php';

		if ( ! is_readable( $source ) || ! wp_is_writable( WPMU_PLUGIN_DIR ) ) {
			return;
		}

		copy( $source, $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- WP_Filesystem is not initialised in the test bootstrap, and this is a local copy of a file the plugin ships.
	}

	/**
	 * Every option currently named for this plugin.
	 *
	 * @return list<string>
	 */
	private function plugin_option_names(): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$names = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
				$wpdb->esc_like( 'basic_firewall_' ) . '%'
			)
		);

		return array_map( 'strval', (array) $names );
	}

	/**
	 * Run the plugin's uninstall.
	 *
	 * `uninstall_plugin()` defines WP_UNINSTALL_PLUGIN and so can only be called
	 * once in a process -- the second test using it dies with "Constant
	 * WP_UNINSTALL_PLUGIN already defined" before reaching any assertion. So the
	 * first call goes through WordPress, which is what proves the real path
	 * works, and later ones include the file directly under the same constant.
	 *
	 * uninstall.php guards its function declarations for exactly this reason.
	 */
	private function run_uninstall(): void {
		if ( ! function_exists( 'uninstall_plugin' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			uninstall_plugin( 'basic-firewall/basic-firewall.php' );

			return;
		}

		include dirname( __DIR__, 2 ) . '/uninstall.php';
	}

	/**
	 * What the last uninstall said it left behind.
	 *
	 * @return list<string>
	 */
	private function uninstall_notes(): array {
		return function_exists( 'basic_firewall_uninstall_notes' ) ? basic_firewall_uninstall_notes() : array();
	}
}
