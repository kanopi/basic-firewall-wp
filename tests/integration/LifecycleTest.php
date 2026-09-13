<?php
/**
 * Activation, deactivation and uninstall.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Install\Activator;
use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use PHPUnit\Framework\TestCase;

/**
 * What the plugin leaves behind, and what it must not.
 *
 * Uninstall is the hardest thing here to test and the easiest to get wrong,
 * because it is the one code path that runs without the plugin's autoloader. It
 * cannot ask Schema what the option is called or Paths where the directory is,
 * so it duplicates that knowledge -- and a duplicate rots.
 *
 * It did. A real uninstall dropped the tables, revoked the capabilities and
 * removed the mu-plugin, then left two options behind and left the entire
 * private directory in place: the block list, the firewall logs and the
 * compiled configuration, in a directory that on nginx is readable over the
 * web. Both were knowledge added to the plugin after uninstall.php was written.
 *
 * These tests exist so that the next thing added to the plugin cannot repeat it.
 */
final class LifecycleTest extends TestCase {

	/**
	 * Options this site had before the test.
	 *
	 * @var array<string, mixed>
	 */
	private array $snapshot = array();

	/**
	 * Snapshot everything the plugin owns.
	 */
	protected function setUp(): void {
		parent::setUp();

		foreach ( $this->plugin_option_names() as $name ) {
			$this->snapshot[ $name ] = get_option( $name, null );
		}
	}

	/**
	 * Put it all back, and leave the site activated.
	 */
	protected function tearDown(): void {
		foreach ( $this->snapshot as $name => $value ) {
			if ( null === $value ) {
				delete_option( (string) $name );
			} else {
				update_option( (string) $name, $value, false );
			}
		}

		Plugin::instance()->settings()->flush();
		Capabilities::grant();
		Plugin::instance()->paths()->ensure();
		Plugin::instance()->compiled()->rebuild();

		parent::tearDown();
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
	 * Activation writes the safe defaults and grants the capabilities.
	 */
	public function test_activation_installs_safely(): void {
		/*
		 * Activation is RUN here, against a site with no settings, rather than
		 * inspected on whatever the site happens to hold.
		 *
		 * The first version of this read the live settings and asserted the mode
		 * was "log". It passed only because the site under test happened to be
		 * in log mode, and failed the moment somebody left a blocking rule set
		 * behind -- reporting a safety property as broken when nothing was. A
		 * test that asserts on ambient state is a test that reports on the last
		 * thing that touched the site.
		 */
		delete_option( Schema::OPTION );
		delete_option( Schema::VERSION_OPTION );

		Plugin::instance()->settings()->flush();

		Activator::activate();

		Plugin::instance()->settings()->flush();

		$settings = Plugin::instance()->settings();

		$this->assertTrue( $settings->is_installed(), 'Activation did not write the settings option.' );
		$this->assertSame( 'log', $settings->get( 'global.mode' ), 'A fresh install must not be blocking.' );
		$this->assertSame( array(), $settings->get( 'rules' ), 'A fresh install must ship no rules.' );

		foreach ( Capabilities::all() as $capability ) {
			$this->assertTrue(
				get_role( 'administrator' )->has_cap( $capability ),
				sprintf( 'The administrator role was not granted %s.', $capability )
			);
		}

		$this->assertSame(
			Schema::VERSION,
			(int) get_option( Schema::VERSION_OPTION ),
			'The schema version was not recorded, so the upgrade routines would run against a fresh install.'
		);
	}

	/**
	 * The option is not autoloaded.
	 *
	 * The whole reason a single option is safe for a large rule set: nothing on
	 * the front end reads it, so it must not be unserialised on every request.
	 */
	public function test_the_settings_option_is_not_autoloaded(): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$autoload = $wpdb->get_var(
			$wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", Schema::OPTION )
		);

		$this->assertNotContains(
			(string) $autoload,
			array( 'yes', 'on', 'auto' ),
			'The settings option is autoloaded, so every front-end request pays to unserialise the rule set.'
		);
	}

	/**
	 * Uninstall removes every option, by prefix rather than from a list.
	 *
	 * Asserted against a synthetic option the plugin has never written, because
	 * the failure being guarded against is precisely an option nobody remembered
	 * to add to a list.
	 */
	public function test_uninstall_removes_options_it_was_never_told_about(): void {
		update_option( 'basic_firewall_a_future_option', 'value', false );
		set_transient( 'basic_firewall_a_future_transient', 'value', 60 );

		$this->run_uninstall();

		$this->assertSame(
			array(),
			$this->plugin_option_names(),
			'Uninstall left plugin options behind.'
		);

		$this->assertFalse(
			get_transient( 'basic_firewall_a_future_transient' ),
			'Uninstall left a transient behind.'
		);
	}

	/**
	 * Uninstall removes the private directory, suffix and all.
	 *
	 * The directory holds the block list, the logs and the compiled
	 * configuration. Leaving it is not untidiness: on nginx it is readable over
	 * the web, and uninstalling is exactly when nobody is watching for that.
	 */
	public function test_uninstall_removes_the_private_directory(): void {
		$base = Plugin::instance()->paths()->base();

		Plugin::instance()->paths()->ensure();

		$this->assertDirectoryExists( $base, 'The private directory was not there to begin with.' );
		$this->assertStringContainsString(
			'basic-firewall-private-',
			$base,
			'The directory no longer carries the random suffix this test is about.'
		);

		$this->run_uninstall();

		$this->assertDirectoryDoesNotExist(
			$base,
			'Uninstall left the private directory in place, with the block list and logs in it.'
		);
	}

	/**
	 * Uninstall drops the tables and revokes the capabilities.
	 */
	public function test_uninstall_drops_tables_and_revokes_capabilities(): void {
		global $wpdb;

		$table = $wpdb->prefix . 'basic_firewall_log';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( "CREATE TABLE IF NOT EXISTS `{$table}` ( id BIGINT AUTO_INCREMENT PRIMARY KEY, message TEXT )" );

		$this->run_uninstall();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$remaining = $wpdb->get_col(
			$wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->prefix . 'basic_firewall' ) . '%' )
		);

		$this->assertSame( array(), (array) $remaining, 'Uninstall left tables behind.' );

		foreach ( Capabilities::all() as $capability ) {
			$this->assertFalse(
				get_role( 'administrator' )->has_cap( $capability ),
				sprintf( 'Uninstall left %s granted.', $capability )
			);
		}
	}

	/**
	 * The upgrade routines are idempotent and advance the recorded version.
	 */
	public function test_upgrade_routines_are_idempotent(): void {
		update_option( Schema::VERSION_OPTION, 0, false );

		Upgrader::maybe_upgrade();

		$this->assertSame(
			Schema::VERSION,
			(int) get_option( Schema::VERSION_OPTION ),
			'The upgrade did not advance the schema version.'
		);

		$this->assertNull( Upgrader::failure(), 'The upgrade reported a failure.' );

		// Running again must change nothing and must not fail.
		Upgrader::maybe_upgrade();

		$this->assertSame( Schema::VERSION, (int) get_option( Schema::VERSION_OPTION ) );
		$this->assertNull( Upgrader::failure() );
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
}
