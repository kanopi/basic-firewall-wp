<?php
/**
 * Uninstall removes what the plugin wrote outside the default private directory.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Paths;
use Kanopi\BasicFirewall\Support\Schema;
use PHPUnit\Framework\TestCase;

/**
 * Every place the plugin can write, and the places it must not delete from.
 *
 * Uninstall used to remove `uploads/basic-firewall-private-*` and nothing else.
 * The block list and the logs hold IP addresses and request headers, and they
 * were left behind wherever an administrator had moved them: a private
 * directory put outside the web root with the filter the README recommends,
 * the WP_CONTENT_DIR fallback, an absolute storage or log path, a cache
 * directory, Redis, the object cache and APCu.
 *
 * Each location has a test here, and so does the other half of the promise:
 * a stored path can point anywhere, so uninstall deletes only inside
 * directories the plugin created or guards, never follows a symlink out, and
 * says what it left rather than leaving it silently.
 */
final class UninstallLeftoversTest extends TestCase {

	use Uninstall_Harness;
	use Test_Services;

	/**
	 * A scratch directory for this test, outside the site.
	 *
	 * @var string
	 */
	private string $tmp = '';

	/**
	 * The private-path filter this test added, if any.
	 *
	 * @var (callable(): string)|null
	 */
	private $filter = null;

	/**
	 * Snapshot the site and make a scratch directory.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->snapshot_plugin_state();

		$this->tmp = rtrim( sys_get_temp_dir(), '/' ) . '/bfw-uninstall-' . bin2hex( random_bytes( 6 ) );
		wp_mkdir_p( $this->tmp );
	}

	/**
	 * Drop the filter, restore the site, delete the scratch directory.
	 */
	protected function tearDown(): void {
		if ( null !== $this->filter ) {
			remove_filter( 'basic_firewall_private_path', $this->filter );
			$this->filter = null;
		}

		$this->restore_plugin_state();
		$this->remove_tree( $this->tmp );

		parent::tearDown();
	}

	/**
	 * A private directory moved by the filter, and created by the plugin, goes.
	 *
	 * The README recommends the filter for putting the directory outside the
	 * web root. Those are the sites that cared most where the block list went,
	 * and uninstall left it behind on every one of them.
	 */
	public function test_a_filtered_private_directory_the_plugin_created_is_removed(): void {
		$dir = $this->filter_private_path( $this->tmp . '/private' );

		$this->assertSame( array(), Plugin::instance()->paths()->ensure() );
		$this->assertFileExists( $dir . '/' . Paths::OWNER_MARKER, 'ensure() did not mark the directory it created.' );

		$this->write( $dir . '/blocked.data' );
		$this->write( $dir . '/logs/firewall-2026-09-28.log' );

		$this->run_uninstall();

		$this->assertDirectoryDoesNotExist( $dir, 'Uninstall left a filtered private directory the plugin itself created.' );
	}

	/**
	 * A filtered directory that already existed keeps what is not the plugin's.
	 *
	 * The filter can name a directory somebody made by hand and keeps other
	 * things in. ensure() writes its guard files there all the same, which is
	 * why a guard file proves the plugin wrote into a directory and not that
	 * it owns it.
	 */
	public function test_a_filtered_directory_that_already_existed_keeps_what_is_not_the_plugins(): void {
		$dir = $this->tmp . '/shared';
		$this->write( $dir . '/notes.txt', 'somebody else' );
		$this->filter_private_path( $dir );

		Plugin::instance()->paths()->ensure();

		$this->assertFileDoesNotExist( $dir . '/' . Paths::OWNER_MARKER, 'ensure() claimed a directory it did not create.' );

		$this->write( $dir . '/blocked.data' );
		$this->write( $dir . '/firewall.yml' );
		$this->write( $dir . '/logs/firewall-2026-09-28.log' );

		// The runtime sidecar, where Paths says it goes. Found missing from
		// uninstall's list in #56: the compiler writes it whenever the
		// firewall is switched off or pinned, and it outlived the plugin.
		$this->assertSame( $dir . '/runtime.json', Plugin::instance()->paths()->runtime_file() );
		$this->write( Plugin::instance()->paths()->runtime_file(), '{"enabled":false}' );

		$this->run_uninstall();

		$this->assertFileExists( $dir . '/notes.txt', 'Uninstall deleted a file the plugin never wrote.' );

		foreach ( array( 'blocked.data', 'firewall.yml', 'runtime.json', 'logs', '.htaccess', 'web.config', 'index.php' ) as $name ) {
			$this->assertFileDoesNotExist( $dir . '/' . $name, sprintf( 'Uninstall left the plugin\'s %s in a guarded directory.', $name ) );
		}

		$this->assertNoteMentions( $dir );
	}

	/**
	 * A filtered directory with no sign of the plugin is not touched.
	 */
	public function test_a_filtered_directory_with_no_guard_files_is_left_alone(): void {
		$dir = $this->tmp . '/unguarded';
		$this->write( $dir . '/blocked.data' );
		$this->filter_private_path( $dir );

		$this->run_uninstall();

		$this->assertFileExists( $dir . '/blocked.data', 'Uninstall deleted from a directory that carries no sign of the plugin.' );
		$this->assertNoteMentions( $dir );
	}

	/**
	 * The WP_CONTENT_DIR fallback is removed too.
	 *
	 * Paths::default_base() falls back to wp-content when the uploads directory
	 * is unavailable, and uninstall only ever looked under uploads.
	 */
	public function test_the_wp_content_fallback_is_removed(): void {
		$dir = rtrim( WP_CONTENT_DIR, '/' ) . '/basic-firewall-private-' . bin2hex( random_bytes( 8 ) );

		$this->write( $dir . '/blocked.data' );
		$this->write( $dir . '/logs/firewall.log' );

		try {
			$this->run_uninstall();

			$this->assertDirectoryDoesNotExist( $dir, 'Uninstall left the WP_CONTENT_DIR fallback private directory.' );
		} finally {
			$this->remove_tree( $dir );
		}
	}

	/**
	 * Stored paths are removed only where the plugin created or guards the directory.
	 *
	 * An absolute path an administrator typed can name anything: a log handler
	 * pointed at `/var/log/syslog` is a valid configuration. Three directories
	 * here -- one the plugin made, one it guards, one it has never seen -- and
	 * only the last keeps its files.
	 */
	public function test_stored_paths_are_removed_only_where_the_plugin_vouches_for_them(): void {
		$owned   = $this->owned_dir( $this->tmp . '/owned' );
		$guarded = $this->guarded_dir( $this->tmp . '/guarded' );
		$foreign = $this->tmp . '/foreign';

		$this->write( $owned . '/blocked.data' );
		$this->write( $owned . '/blocked.data.lock' );
		$this->write( $owned . '/blocked.data.123.tmp' );
		$this->write( $foreign . '/offenses.data' );
		$this->write( $foreign . '/ratelimit.data' );
		$this->write( $guarded . '/firewall.log' );
		$this->write( $guarded . '/firewall-2026-09-28.log' );
		$this->write( $guarded . '/firewall-notes.log' );
		$this->write( $owned . '/counters.data' );

		$this->given_settings(
			array(
				'storage' => array(
					'file' => array(
						'storage_file' => $owned . '/blocked.data',
						'offense_file' => $foreign . '/offenses.data',
					),
				),
				'logger'  => array(
					array(
						'type' => 'rotating_file',
						'path' => $guarded . '/firewall.log',
					),
				),
				'rules'   => array(
					$this->rate_limit_rule( array( 'file' => $foreign . '/ratelimit.data' ) ),
					$this->rate_limit_rule( array( 'file' => $owned . '/counters.data' ) ),
				),
			)
		);

		$this->run_uninstall();

		foreach ( array( 'blocked.data', 'blocked.data.lock', 'blocked.data.123.tmp', 'counters.data' ) as $name ) {
			$this->assertFileDoesNotExist( $owned . '/' . $name, sprintf( 'Uninstall left %s in a directory the plugin created.', $name ) );
		}

		$this->assertFileDoesNotExist( $guarded . '/firewall.log', 'Uninstall left a log file in a guarded directory.' );
		$this->assertFileDoesNotExist( $guarded . '/firewall-2026-09-28.log', 'Uninstall left a rotated log file behind.' );
		$this->assertFileExists( $guarded . '/firewall-notes.log', 'Uninstall deleted a file that only resembles a rotated log.' );
		$this->assertDirectoryExists( $owned, 'A directory holding a stored path is not the private directory, and is not removed.' );

		$this->assertFileExists( $foreign . '/offenses.data', 'Uninstall deleted a file outside any directory the plugin vouches for.' );
		$this->assertFileExists( $foreign . '/ratelimit.data', 'Uninstall deleted a rate limit file outside any directory the plugin vouches for.' );
		$this->assertNoteMentions( $foreign . '/offenses.data' );
		$this->assertNoteMentions( $foreign . '/ratelimit.data' );
	}

	/**
	 * A symlink is removed as a link, and never followed.
	 */
	public function test_symlinks_are_removed_as_links_and_never_followed(): void {
		$dir     = $this->filter_private_path( $this->tmp . '/private' );
		$foreign = $this->tmp . '/foreign';

		Plugin::instance()->paths()->ensure();

		$this->write( $foreign . '/target.data', 'not the plugin\'s' );
		$this->write( $foreign . '/tree/keep.txt', 'not the plugin\'s' );

		// phpcs:disable WordPress.WP.AlternativeFunctions -- symlink() has no WordPress wrapper.
		symlink( $foreign . '/target.data', $dir . '/blocked.data' );
		symlink( $foreign . '/tree', $dir . '/logs-elsewhere' );
		// phpcs:enable

		$this->run_uninstall();

		$this->assertDirectoryDoesNotExist( $dir );
		$this->assertFileExists( $foreign . '/target.data', 'Uninstall followed a symlinked file out of the private directory.' );
		$this->assertFileExists( $foreign . '/tree/keep.txt', 'Uninstall followed a symlinked directory out of the private directory.' );
	}

	/**
	 * The files cache backend's pools go, and the directory they sit in stays.
	 */
	public function test_the_cache_directory_pools_are_removed(): void {
		$dir = $this->tmp . '/cache-dir';

		$this->write( $dir . '/basic_firewall_agents/a/b/item' );
		$this->write( $dir . '/basic_firewall_rdns/c/d/item' );
		$this->write( $dir . '/somebody-else/item' );

		$this->given_settings(
			array(
				'cache' => array(
					'backend'   => 'filesystem',
					'directory' => $dir,
				),
			)
		);

		$this->run_uninstall();

		$this->assertDirectoryDoesNotExist( $dir . '/basic_firewall_agents', 'Uninstall left the agent corpus pool.' );
		$this->assertDirectoryDoesNotExist( $dir . '/basic_firewall_rdns', 'Uninstall left the reverse-DNS verdict pool.' );
		$this->assertFileExists( $dir . '/somebody-else/item', 'Uninstall deleted from the cache directory beyond the plugin\'s pools.' );
	}

	/**
	 * BASIC_FIREWALL_CACHE_DIR is emptied of the library's caches, under the ownership guard.
	 *
	 * A constant cannot be defined and undefined inside one test process, so
	 * this calls the function uninstall.php calls with it -- after a real
	 * uninstall, which is what declares the function.
	 */
	public function test_the_cache_dir_constant_directory_is_cleared_under_the_guard(): void {
		$this->run_uninstall();

		$this->assertTrue( function_exists( 'basic_firewall_uninstall_cache_constant_dir' ) );

		$named = $this->tmp . '/basic-firewall-cache';
		$this->write( $named . '/compiled/firewall.php' );
		$this->write( $named . '/sources/list.body' );
		$this->write( $named . '/device-detector/a/b/item' );
		$this->write( $named . '/kanopi_firewall_rdns/a/b/item' );
		$this->write( $named . '/abuseipdb/verdict' );
		$this->write( $named . '/' . md5( 'https://example.com/list' ) . '.cache' );
		$this->write( $named . '/keep.txt' );

		$owned = $this->owned_dir( $this->tmp . '/owned-cache' );
		$this->write( $owned . '/compiled/firewall.php' );

		$shared = $this->tmp . '/shared';
		$this->write( $shared . '/compiled/firewall.php' );

		basic_firewall_uninstall_notes( null, true );

		\basic_firewall_uninstall_cache_constant_dir( $named );
		\basic_firewall_uninstall_cache_constant_dir( $owned );
		\basic_firewall_uninstall_cache_constant_dir( $shared );

		foreach ( array( 'compiled', 'sources', 'device-detector', 'kanopi_firewall_rdns', 'abuseipdb', md5( 'https://example.com/list' ) . '.cache' ) as $name ) {
			$this->assertFileDoesNotExist( $named . '/' . $name, sprintf( 'Uninstall left %s in the cache directory.', $name ) );
		}

		$this->assertFileExists( $named . '/keep.txt', 'Uninstall deleted something from the cache directory that the library never writes.' );
		$this->assertDirectoryExists( $named, 'Uninstall removed a cache directory it did not create.' );
		$this->assertDirectoryDoesNotExist( $owned, 'Uninstall left a cache directory the plugin created.' );
		$this->assertFileExists( $shared . '/compiled/firewall.php', 'Uninstall deleted from a cache directory with no sign of the plugin -- it could have been /tmp.' );
		$this->assertNoteMentions( $shared );
	}

	/**
	 * The Redis block list and rate limit counters are deleted by prefix, and nothing else.
	 *
	 * Needs a Redis server: see Test_Services::redis_server(). CI runs one;
	 * the DDEV site this suite usually runs in has ext-redis and no server, so
	 * it skips there unless BASIC_FIREWALL_TEST_REDIS points at one. Every key
	 * it writes carries a random prefix, so a shared server is safe to use.
	 */
	public function test_redis_keys_under_the_plugins_prefixes_are_deleted(): void {
		list( $host, $port ) = $this->redis_server();

		$redis  = new \Redis();
		$run    = bin2hex( random_bytes( 4 ) );
		$block  = 'bfwtest:' . $run . ':';
		$counts = 'bfwtest-rl:' . $run . ':';
		$other  = 'bfwtest-foreign:' . $run;

		$redis->connect( $host, $port, 1.0 );
		$redis->set( $block . 'block:203.0.113.9', '{}' );
		$redis->zAdd( $block . 'offense:203.0.113.9', time(), 'x' );
		$redis->set( $counts . '203.0.113.9', '3' );
		$redis->set( $other, 'not the plugin\'s' );

		// A prefix is matched literally, not as a glob.
		$redis->set( 'bfwtest:' . $run . 'X', 'glob neighbour' );

		$this->given_settings(
			array(
				'storage' => array(
					'backend' => 'redis',
					'redis'   => array(
						'host'   => $host,
						'port'   => $port,
						'prefix' => $block,
					),
				),
				'rules'   => array(
					$this->rate_limit_rule(
						array(
							'backend'    => 'redis',
							'redis_host' => $host,
							'redis_port' => $port,
							'key_prefix' => $counts,
						)
					),
				),
			)
		);

		try {
			$this->run_uninstall();

			$this->assertSame( 0, (int) $redis->exists( $block . 'block:203.0.113.9' ), 'Uninstall left a block record in Redis.' );
			$this->assertSame( 0, (int) $redis->exists( $block . 'offense:203.0.113.9' ), 'Uninstall left an offense history in Redis.' );
			$this->assertSame( 0, (int) $redis->exists( $counts . '203.0.113.9' ), 'Uninstall left rate limit counters in Redis.' );
			$this->assertSame( 1, (int) $redis->exists( $other ), 'Uninstall deleted a Redis key outside its prefix.' );
			$this->assertSame( 1, (int) $redis->exists( 'bfwtest:' . $run . 'X' ), 'Uninstall treated its prefix as a glob.' );
		} finally {
			$redis->del( array( $other, 'bfwtest:' . $run . 'X', $block . 'block:203.0.113.9', $block . 'offense:203.0.113.9', $counts . '203.0.113.9' ) );
			$redis->close();
		}
	}

	/**
	 * An unreachable Redis server is noted, not fatal.
	 */
	public function test_an_unreachable_redis_server_is_noted_and_not_fatal(): void {
		if ( ! class_exists( 'Redis' ) ) {
			$this->markTestSkipped( 'ext-redis is not loaded, so the connection path is never reached.' );
		}

		$this->given_settings(
			array(
				'storage' => array(
					'backend' => 'redis',
					'redis'   => array(
						'host'   => '127.0.0.1',
						'port'   => 1,
						'prefix' => 'bfwtest-unreachable:',
					),
				),
			)
		);

		$this->run_uninstall();

		$this->assertSame( array(), $this->plugin_option_names(), 'An unreachable Redis server stopped the rest of the uninstall.' );
		$this->assertNoteMentions( 'bfwtest-unreachable:' );
	}

	/**
	 * The plugin's object cache group is flushed, and no other.
	 */
	public function test_the_object_cache_group_is_flushed(): void {
		if ( ! wp_cache_supports( 'flush_group' ) ) {
			$this->markTestSkipped( 'This object cache cannot flush one group.' );
		}

		wp_cache_set( 'corpus', 'cached', 'basic_firewall' );
		wp_cache_set( 'corpus', 'cached', 'bfwtest_other' );

		$this->run_uninstall();

		$this->assertFalse( wp_cache_get( 'corpus', 'basic_firewall' ), 'Uninstall left entries in the plugin\'s object cache group.' );
		$this->assertSame( 'cached', wp_cache_get( 'corpus', 'bfwtest_other' ), 'Uninstall flushed another group.' );

		wp_cache_delete( 'corpus', 'bfwtest_other' );
	}

	/**
	 * The plugin's APCu entries are deleted, and no others.
	 */
	public function test_apcu_entries_are_deleted(): void {
		$this->requires_apcu();

		apcu_store( 'basic_firewall_agents:bfwtest', 'cached' );
		apcu_store( 'bfwtest_other:bfwtest', 'cached' );

		$this->run_uninstall();

		$this->assertFalse( apcu_exists( 'basic_firewall_agents:bfwtest' ), 'Uninstall left the plugin\'s APCu entries.' );
		$this->assertTrue( apcu_exists( 'bfwtest_other:bfwtest' ), 'Uninstall deleted another APCu entry.' );

		apcu_delete( 'bfwtest_other:bfwtest' );
	}

	/**
	 * On a network, every site is visited.
	 */
	public function test_every_site_of_a_network_is_uninstalled(): void {
		$this->requires_multisite();

		$sites = array_map(
			'intval',
			get_sites(
				array(
					'fields' => 'ids',
					'number' => 2,
				)
			)
		);

		foreach ( $sites as $site ) {
			switch_to_blog( $site );
			update_option( 'basic_firewall_bfwtest', 'value', false );
			restore_current_blog();
		}

		$this->run_uninstall();

		foreach ( $sites as $site ) {
			switch_to_blog( $site );
			$left = get_option( 'basic_firewall_bfwtest', null );
			restore_current_blog();

			$this->assertNull( $left, sprintf( 'Uninstall left site %d\'s data behind.', $site ) );
		}
	}

	/**
	 * Point the private directory somewhere, as a site would with the filter.
	 *
	 * @param string $dir Directory.
	 */
	private function filter_private_path( string $dir ): string {
		$this->filter = static fn (): string => $dir;

		add_filter( 'basic_firewall_private_path', $this->filter );
		Plugin::instance()->paths()->reset();

		return $dir;
	}

	/**
	 * Write the settings document, over the defaults.
	 *
	 * Written raw rather than through Settings, because uninstall reads the
	 * raw option -- and so the test controls exactly what it reads.
	 *
	 * @param array<string, mixed> $overrides Values merged over the stored document.
	 */
	private function given_settings( array $overrides ): void {
		$current = get_option( Schema::OPTION, array() );

		update_option( Schema::OPTION, array_replace_recursive( is_array( $current ) ? $current : array(), $overrides ), false );
	}

	/**
	 * A rate limit rule carrying the given counter storage.
	 *
	 * @param array<string, mixed> $storage Counter storage settings.
	 *
	 * @return array<string, mixed>
	 */
	private function rate_limit_rule( array $storage ): array {
		return array(
			'id'       => 'bfwtest-' . bin2hex( random_bytes( 4 ) ),
			'type'     => 'rate_limit',
			'enabled'  => true,
			'settings' => array( 'storage' => $storage + array( 'backend' => 'file' ) ),
		);
	}

	/**
	 * A directory as the plugin creates one, marker and all.
	 *
	 * @param string $dir Directory.
	 */
	private function owned_dir( string $dir ): string {
		$this->write( $dir . '/' . Paths::OWNER_MARKER, 'Created by the Basic Firewall plugin.' );

		return $dir;
	}

	/**
	 * A directory carrying the plugin's guard file, but not its marker.
	 *
	 * @param string $dir Directory.
	 */
	private function guarded_dir( string $dir ): string {
		$this->write( $dir . '/.htaccess', "# Basic Firewall private directory. Written by the plugin; edits are overwritten.\n" );

		return $dir;
	}

	/**
	 * Write a file, creating its directory.
	 *
	 * @param string $path     File.
	 * @param string $contents Contents.
	 */
	private function write( string $path, string $contents = 'data' ): void {
		wp_mkdir_p( dirname( $path ) );

		file_put_contents( $path, $contents ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- a test fixture.
	}

	/**
	 * Assert that uninstall said it left something mentioning this.
	 *
	 * @param string $needle Path or prefix.
	 */
	private function assertNoteMentions( string $needle ): void {
		$notes = $this->uninstall_notes();

		foreach ( $notes as $note ) {
			if ( false !== strpos( $note, $needle ) ) {
				$this->addToAssertionCount( 1 );

				return;
			}
		}

		$this->fail( sprintf( "Uninstall left %s without saying so. It said:\n%s", $needle, implode( "\n", $notes ) ) );
	}

	/**
	 * Remove a scratch tree, links as links.
	 *
	 * @param string $dir Directory.
	 */
	private function remove_tree( string $dir ): void {
		if ( '' === $dir || ! is_dir( $dir ) || is_link( $dir ) ) {
			return;
		}

		foreach ( (array) scandir( $dir ) as $entry ) {
			if ( '.' === $entry || '..' === $entry ) {
				continue;
			}

			$path = $dir . '/' . $entry;

			if ( is_dir( $path ) && ! is_link( $path ) ) {
				$this->remove_tree( $path );
			} else {
				unlink( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- a test fixture.
			}
		}

		rmdir( $dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- a test fixture.
	}
}
