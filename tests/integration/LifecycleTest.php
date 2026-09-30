<?php
/**
 * Activation, deactivation and uninstall.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
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

	use Uninstall_Harness;

	/**
	 * Snapshot everything the plugin owns.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->snapshot_plugin_state();
	}

	/**
	 * Put it all back, and leave the site activated. See Uninstall_Harness.
	 */
	protected function tearDown(): void {
		$this->restore_plugin_state();

		parent::tearDown();
	}

	/**
	 * The mu-plugin loader's absence is reported, even when it is not in use.
	 *
	 * This is the check that was missing while the bug above went unnoticed.
	 * Site Health returned early on the wp-config.php path and never looked at
	 * the loader, so the one screen that could have said it was gone reported
	 * the better answer instead.
	 */
	public function test_a_missing_mu_loader_is_reported(): void {
		$target = WPMU_PLUGIN_DIR . '/basic-firewall-loader.php';
		$backup = $target . '.test-backup';

		if ( ! file_exists( $target ) ) {
			$this->markTestSkipped( 'The loader is not installed on this site, so there is nothing to hide.' );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- WP_Filesystem is not initialised in the test bootstrap.
		rename( $target, $backup );

		try {
			$result = Site_Health::results()['evaluation'];

			$this->assertNotSame(
				'good',
				$result['status'],
				'A missing mu-plugin loader was reported as healthy, so nothing would tell an administrator the fallback had gone.'
			);

			$this->assertStringContainsStringIgnoringCase(
				'mu-plugin',
				wp_strip_all_tags( $result['label'] . ' ' . $result['description'] ),
				'The result does not mention the mu-plugin, so it does not say what is actually wrong.'
			);
		} finally {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- restoring the file this test moved.
			rename( $backup, $target );
		}
	}

	/**
	 * Deactivating removes the runtime on a single site, and keeps settings.
	 *
	 * On a network the loader is left while another site still runs the
	 * plugin; on a single site there is no other site, so it goes. The
	 * harness puts the loader and the compiled file back.
	 */
	public function test_deactivation_removes_the_runtime_on_a_single_site(): void {
		if ( is_multisite() ) {
			$this->markTestSkipped( 'A single-site assertion.' );
		}

		if ( ! file_exists( WPMU_PLUGIN_DIR . '/basic-firewall-loader.php' ) ) {
			$this->markTestSkipped( 'The loader is not installed on this site, so there is nothing to remove.' );
		}

		$settings = get_option( Schema::OPTION );

		Activator::deactivate();

		$this->assertFileDoesNotExist( WPMU_PLUGIN_DIR . '/basic-firewall-loader.php', 'Deactivating on a single site left the loader evaluating requests.' );
		$this->assertFileDoesNotExist( Plugin::instance()->paths()->compiled_file() );
		$this->assertSame( $settings, get_option( Schema::OPTION ), 'Deactivating touched the settings.' );
	}

	/**
	 * The wp-config.php snippet gets a check of its own.
	 *
	 * Separate from the evaluation point on purpose: that test folds the
	 * snippet, the mu-plugin and any page cache into one answer, and so reports
	 * a healthy site when the single item somebody came looking for is absent.
	 */
	public function test_the_bootstrap_snippet_has_its_own_check(): void {
		$results = Site_Health::results();

		$this->assertArrayHasKey(
			'bootstrap',
			$results,
			'There is no check reporting whether wp-config.php calls the firewall.'
		);

		$this->assertContains(
			$results['bootstrap']['status'],
			array( 'good', 'recommended', 'critical' ),
			'The bootstrap check did not return a usable status.'
		);

		/*
		 * Asserted against the bootstrap's own report rather than against this
		 * site's wp-config.php, so the test says the same thing on a machine
		 * that runs the early path and one that does not.
		 *
		 * Inverted on a network, where the snippet steps aside: its absence
		 * is the healthy state there, and its presence is a recommendation
		 * to remove it (MultisiteTest).
		 */
		$this->assertSame(
			is_multisite() ? ! Site_Health::early_report()['called'] : Site_Health::early_report()['called'],
			'good' === $results['bootstrap']['status'],
			'The check disagrees with whether the bootstrap actually ran, which is the only thing that proves the snippet is doing anything.'
		);
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
	 * The "send events to WordPress" settings are gone, from the option too.
	 *
	 * Nothing ever forwarded anything. Routine 8 rewrites the option, and
	 * the settings service drops the keys wherever a document is read or
	 * written, so an old export cannot bring them back.
	 */
	public function test_retired_logging_settings_are_dropped(): void {
		$document                            = (array) get_option( Schema::OPTION, Schema::defaults() );
		$document['logging']                 = (array) ( $document['logging'] ?? array() );
		$document['logging']['to_wordpress'] = true;
		$document['logging']['wp_level']     = 'error';
		$document['logging']['redact_extra'] = array( 'header.x-kept' );

		update_option( Schema::OPTION, $document, false );
		update_option( Schema::VERSION_OPTION, 7, false );
		Plugin::instance()->settings()->flush();

		$this->assertArrayNotHasKey( 'to_wordpress', Plugin::instance()->settings()->get( 'logging' ), 'A retired setting is still read, and so still exported.' );

		Upgrader::maybe_upgrade();

		$stored = (array) get_option( Schema::OPTION );

		$this->assertSame( Schema::VERSION, (int) get_option( Schema::VERSION_OPTION ) );
		$this->assertArrayNotHasKey( 'to_wordpress', (array) $stored['logging'], 'The upgrade left the retired setting in the option.' );
		$this->assertArrayNotHasKey( 'wp_level', (array) $stored['logging'] );
		$this->assertSame( array( 'header.x-kept' ), $stored['logging']['redact_extra'], 'The upgrade took a live setting with it.' );

		// And a document carrying them, as an old export does, stores without them.
		$document['logging']['to_wordpress'] = true;

		Plugin::instance()->settings()->replace( $document );

		$this->assertArrayNotHasKey( 'to_wordpress', (array) ( (array) get_option( Schema::OPTION ) )['logging'] );
	}
}
