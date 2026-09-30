<?php
/**
 * The plugin on a multisite network.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Install\Activator;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use PHPUnit\Framework\TestCase;

/**
 * What differs on a network, proved on a real one.
 *
 * Each of these was written with a note saying it had no automated test,
 * because CI had no network to run it on (#43). The CI job
 * `integration-multisite-*` installs a subdirectory network with a second
 * site, network-activates the plugin and sets BASIC_FIREWALL_MULTISITE=1, so
 * these fail there rather than skip; on a single site they skip.
 *
 * @covers \Kanopi\BasicFirewall\Install\Activator
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class MultisiteTest extends TestCase {

	use Uninstall_Harness;
	use Test_Services;

	/**
	 * Where the loader lives.
	 */
	private const LOADER = 'basic-firewall-loader.php';

	/**
	 * The bootstrap's report as this process had it.
	 *
	 * @var mixed
	 */
	private $early;

	/**
	 * The network's plugin activation state, put back afterwards.
	 *
	 * @var array{sitewide: mixed, sites: array<int, mixed>}
	 */
	private array $activation = array(
		'sitewide' => null,
		'sites'    => array(),
	);

	/**
	 * Every site's own basic_firewall_* options, put back afterwards.
	 *
	 * The harness restores the site the suite runs as; uninstall visits the
	 * rest too.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private array $other_sites = array();

	/**
	 * Skip off a network, and snapshot what the tests change.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->requires_multisite();

		$this->early = $GLOBALS['basic_firewall_early'] ?? null;

		$this->snapshot_plugin_state();

		$this->activation['sitewide'] = get_site_option( 'active_sitewide_plugins', array() );

		foreach ( $this->site_ids() as $site ) {
			$this->activation['sites'][ $site ] = get_blog_option( $site, 'active_plugins', array() );

			if ( get_current_blog_id() !== $site ) {
				switch_to_blog( $site );
				$this->other_sites[ $site ] = array();

				foreach ( $this->plugin_option_names() as $name ) {
					$this->other_sites[ $site ][ $name ] = get_option( $name );
				}

				restore_current_blog();
			}
		}
	}

	/**
	 * Put the network back as it was, loader, activation and options.
	 */
	protected function tearDown(): void {
		if ( ! is_multisite() ) {
			parent::tearDown();

			return;
		}

		$GLOBALS['basic_firewall_early'] = $this->early;

		update_site_option( 'active_sitewide_plugins', $this->activation['sitewide'] );

		foreach ( $this->activation['sites'] as $site => $plugins ) {
			update_blog_option( $site, 'active_plugins', $plugins );
		}

		foreach ( $this->other_sites as $site => $options ) {
			switch_to_blog( $site );

			foreach ( $this->plugin_option_names() as $name ) {
				if ( ! array_key_exists( $name, $options ) ) {
					delete_option( $name );
				}
			}

			foreach ( $options as $name => $value ) {
				update_option( $name, $value, false );
			}

			restore_current_blog();
		}

		Plugin::instance()->paths()->reset();
		$this->restore_plugin_state();

		parent::tearDown();
	}

	/**
	 * The early path steps aside on this network, with nothing but wp-config.php's constants to go on.
	 *
	 * EarlyPathExceptionModeTest proves this with a fixture that defines the
	 * constants when a header asks it to. Here they are the ones WP-CLI wrote
	 * into a real network's wp-config.php, read by the bootstrap with no
	 * `multisite` option passed.
	 */
	public function test_the_early_path_steps_aside_on_this_network(): void {
		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

		$this->assertTrue( defined( 'MULTISITE' ) && MULTISITE, 'This network\'s wp-config.php does not define MULTISITE, so it is not the network the test is about.' );
		$this->assertTrue( basic_firewall_is_multisite( basic_firewall_options() ), 'The bootstrap did not recognise a real network from its wp-config.php constants.' );

		$log      = (string) tempnam( sys_get_temp_dir(), 'bfw-ms-log' );
		$previous = ini_set( 'error_log', $log ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- captured, and put back.

		try {
			$result = basic_firewall_evaluate(
				array(
					'private_path' => Plugin::instance()->paths()->base(),
					'plugin_path'  => dirname( __DIR__, 2 ),
				)
			);
		} finally {
			ini_set( 'error_log', (string) $previous ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- put back.
			wp_delete_file( $log );
		}

		$this->assertTrue( $result, 'The bootstrap held up a request on a network.' );
		$this->assertSame( 'multisite', $GLOBALS['basic_firewall_early']['reason'] ?? null );
		$this->assertFalse( (bool) ( $GLOBALS['basic_firewall_early']['evaluated'] ?? true ), 'The request was marked evaluated, so the mu-plugin would not apply the site\'s own rules.' );
		$this->assertArrayNotHasKey( 'compiled', (array) $GLOBALS['basic_firewall_early'], 'The bootstrap went on to read a compiled file on a network, which is whichever site\'s it found first.' );
	}

	/**
	 * The network-wide loader survives one site deactivating a network-active plugin.
	 */
	public function test_the_loader_survives_a_site_deactivating_while_network_active(): void {
		$this->given_activation( array(), true );

		$this->as_second_site( static fn () => Activator::deactivate( false ) );

		$this->assertLoaderInstalled( 'One site deactivating removed the loader every other site of the network evaluates through.' );
	}

	/**
	 * Active site by site, the loader stays while another site runs the plugin.
	 */
	public function test_the_loader_survives_while_another_site_is_active(): void {
		$sites = $this->site_ids();

		$this->given_activation( $sites, false );

		$this->as_second_site( static fn () => Activator::deactivate( false ) );

		$this->assertLoaderInstalled( 'Deactivating on one site removed the loader while another site still runs the plugin.' );
	}

	/**
	 * The last site to deactivate takes the loader with it.
	 */
	public function test_the_last_active_site_removes_the_loader(): void {
		$this->given_activation( array( $this->second_site() ), false );

		$this->as_second_site( static fn () => Activator::deactivate( false ) );

		$this->assertFileDoesNotExist( WPMU_PLUGIN_DIR . '/' . self::LOADER, 'The last site running the plugin deactivated it and the loader stayed, evaluating requests for nobody.' );
	}

	/**
	 * Network deactivation removes the loader.
	 */
	public function test_network_deactivation_removes_the_loader(): void {
		$this->given_activation( array(), true );

		Activator::deactivate( true );

		$this->assertFileDoesNotExist( WPMU_PLUGIN_DIR . '/' . self::LOADER, 'Network deactivation left the loader behind.' );
	}

	/**
	 * Site Health on a network: the snippet does nothing, and says so.
	 */
	public function test_site_health_says_the_snippet_does_nothing_on_a_network(): void {
		$GLOBALS['basic_firewall_early'] = array(
			'called'      => true,
			'credentials' => true,
			'evaluated'   => false,
			'reason'      => 'multisite',
		);

		$bootstrap = Site_Health::check( 'bootstrap' );

		$this->assertSame( 'recommended', $bootstrap['status'] );
		$this->assertSame( 'wp-config.php calls the firewall, which does nothing on a multisite network', $bootstrap['label'] );
		$this->assertStringContainsString( 'Remove the require_once line', $bootstrap['description'] );

		$evaluation = Site_Health::check( 'evaluation' );

		$this->assertStringNotContainsString( 'Add this to wp-config.php', $evaluation['description'], 'On a network the evaluation check recommended the snippet, which steps aside there.' );
		$this->assertNotSame( 'wp-config.php calls the firewall bootstrap, which is the earliest any PHP on this site can act.', $evaluation['label'] );

		$this->assertStringContainsString( 'multisite network', Site_Health::early_reason_text( 'multisite' ), 'The reason `wp basic-firewall status` prints for a network does not say what it means.' );
	}

	/**
	 * Site Health on a network without the snippet: healthy, per site.
	 */
	public function test_site_health_is_healthy_on_a_network_without_the_snippet(): void {
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		if ( str_contains( (string) @file_get_contents( ABSPATH . 'wp-config.php' ), 'basic_firewall_evaluate' ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- a local file, read to decide whether this assertion applies.
			$this->markTestSkipped( 'This network\'s wp-config.php carries the snippet.' );
		}

		$bootstrap = Site_Health::check( 'bootstrap' );

		$this->assertSame( 'good', $bootstrap['status'] );
		$this->assertSame( 'Each site of the network evaluates against its own rules', $bootstrap['label'] );
		$this->assertStringNotContainsString( 'Add this to wp-config.php', Site_Health::check( 'evaluation' )['description'] );
	}

	/**
	 * Uninstall visits every site: its options and its own private directory (#11).
	 */
	public function test_uninstall_removes_every_sites_data(): void {
		$sites = array();

		foreach ( $this->site_ids() as $site ) {
			switch_to_blog( $site );
			Plugin::instance()->paths()->reset();
			Plugin::instance()->paths()->ensure();

			$base = Plugin::instance()->paths()->base();

			file_put_contents( $base . '/blocked.data', 'data' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- a test fixture in the site's own private directory.
			update_option( 'basic_firewall_bfwtest', 'value', false );

			if ( false === get_option( Schema::OPTION ) ) {
				update_option( Schema::OPTION, Schema::defaults(), false );
			}

			$sites[ $site ] = $base;

			restore_current_blog();
		}

		Plugin::instance()->paths()->reset();

		$this->assertCount( count( array_unique( $sites ) ), $sites, 'Two sites share one private directory, so this test cannot tell whose uninstall removed it.' );

		$this->run_uninstall();

		foreach ( $sites as $site => $base ) {
			switch_to_blog( $site );
			$left = $this->plugin_option_names();
			restore_current_blog();

			$this->assertSame( array(), $left, sprintf( 'Uninstall left site %d\'s options behind.', $site ) );
			$this->assertDirectoryDoesNotExist( $base, sprintf( 'Uninstall left site %d\'s private directory behind.', $site ) );
		}

		$this->assertFileDoesNotExist( WPMU_PLUGIN_DIR . '/' . self::LOADER, 'Uninstall left the network-wide loader.' );
	}

	/**
	 * Activate the plugin network-wide, or on the given sites only.
	 *
	 * Written straight to the options, as WordPress keeps them, so the test
	 * says which sites are active without running any site's activation.
	 *
	 * @param list<int> $sites    Sites with the plugin in their active_plugins.
	 * @param bool      $sitewide Whether it is network-active.
	 */
	private function given_activation( array $sites, bool $sitewide ): void {
		$basename = plugin_basename( BASIC_FIREWALL_FILE );
		$network  = (array) get_site_option( 'active_sitewide_plugins', array() );

		unset( $network[ $basename ] );

		if ( $sitewide ) {
			$network[ $basename ] = time();
		}

		update_site_option( 'active_sitewide_plugins', $network );

		foreach ( $this->site_ids() as $site ) {
			$active = array_values( array_diff( (array) get_blog_option( $site, 'active_plugins', array() ), array( $basename ) ) );

			if ( in_array( $site, $sites, true ) ) {
				$active[] = $basename;
			}

			update_blog_option( $site, 'active_plugins', $active );
		}

		$this->restore_mu_plugin();
		$this->assertLoaderInstalled( 'The loader is not installed before the test, so its removal proves nothing.' );
	}

	/**
	 * Run something as the network's second site.
	 *
	 * @param callable $callback What to run.
	 */
	private function as_second_site( callable $callback ): void {
		switch_to_blog( $this->second_site() );

		try {
			$callback();
		} finally {
			restore_current_blog();
		}
	}

	/**
	 * The network's sites, the one the suite runs as first.
	 *
	 * @return list<int>
	 */
	private function site_ids(): array {
		$ids = array_map(
			'intval',
			get_sites(
				array(
					'fields' => 'ids',
					'number' => 10,
				)
			)
		);

		usort( $ids, static fn ( int $a, int $b ): int => ( get_current_blog_id() === $b ) <=> ( get_current_blog_id() === $a ) );

		return $ids;
	}

	/**
	 * A site other than the one the suite runs as.
	 */
	private function second_site(): int {
		$sites = $this->site_ids();

		if ( count( $sites ) < 2 ) {
			$this->fail( 'The network has one site. The CI job creates a second with `wp site create`.' );
		}

		return $sites[1];
	}

	/**
	 * Assert the loader is in mu-plugins.
	 *
	 * @param string $message Failure message.
	 */
	private function assertLoaderInstalled( string $message ): void {
		clearstatcache();

		$this->assertFileExists( WPMU_PLUGIN_DIR . '/' . self::LOADER, $message );
	}
}
