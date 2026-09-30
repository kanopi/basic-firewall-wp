<?php
/**
 * Where the firewall caches what it works out.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Storage_Screen;
use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Cache\Cache_Clearer;
use Kanopi\BasicFirewall\Cache\Object_Cache_Adapter;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Firewall;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * The cache backend: what it compiles to, what it hands over live, and clearing.
 *
 * Two mechanisms for one setting, and the tests are arranged around that.
 * Files and APCu are written into the compiled file, so they are asserted on
 * the file -- which is exactly what the wp-config.php path reads. The object
 * cache is handed over as an object at paths the compiler recorded, so the
 * seam that matters is that the recorded path is the one the library reads,
 * and that is proved by evaluating a request through it.
 *
 * @covers \Kanopi\BasicFirewall\Cache\Cache_Backend
 * @covers \Kanopi\BasicFirewall\Cache\Cache_Clearer
 * @covers \Kanopi\BasicFirewall\Cache\Object_Cache_Adapter
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Storage_Screen
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class CacheBackendTest extends Settings_Snapshot {

	use Test_Services;

	/**
	 * A named cache directory, relative so it resolves inside the private directory.
	 */
	private const DIRECTORY = 'test-cache-backend';

	/**
	 * Request globals and the object cache flag, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int, external: bool}
	 */
	private array $globals;

	/**
	 * Remember what the tests change.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->globals = array(
			'get'      => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'post'     => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'user'     => get_current_user_id(),
			'external' => wp_using_ext_object_cache(),
		);
	}

	/**
	 * Put it back, and remove anything written to disk.
	 */
	protected function tearDown(): void {
		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );
		remove_all_filters( 'wp_redirect' );

		$_GET  = $this->globals['get'];
		$_POST = $this->globals['post'];
		wp_set_current_user( $this->globals['user'] );
		wp_using_ext_object_cache( $this->globals['external'] );

		$this->remove_tree( Plugin::instance()->paths()->resolve( self::DIRECTORY ) );

		parent::tearDown();
	}

	/**
	 * The files default names no pool at all.
	 *
	 * Every release before this cached to disk through the library's own
	 * default, and a site that has not chosen anything must compile exactly as
	 * it did. That includes the `cache_dir` key the user agent rule used to
	 * write, which the library never read.
	 */
	public function test_the_files_default_names_no_pool(): void {
		$metadata = $this->compiled_rule_metadata( array( 'backend' => 'filesystem' ) );

		$this->assertArrayNotHasKey( 'cache', $metadata );
		$this->assertArrayNotHasKey( 'cache_dir', $metadata, 'A key the library does not read is not written.' );
		$this->assertArrayNotHasKey( 'verify_cache', $metadata );
	}

	/**
	 * APCu compiles to a class name and scalar arguments, one namespace each.
	 *
	 * Anything the library builds by name has to be expressible in the
	 * compiled file, and this is the reason APCu reaches the wp-config.php
	 * path at all.
	 */
	public function test_apcu_compiles_to_a_class_name(): void {
		$metadata = $this->compiled_rule_metadata(
			array(
				'backend'  => 'apcu',
				'apcu_ttl' => 600,
			)
		);

		$this->assertSame(
			array(
				'adaptor' => Library_Map::CACHE_POOLS['apcu'],
				'args'    => array( Cache_Backend::AGENTS, 600 ),
			),
			$metadata['cache'] ?? null
		);
		$this->assertSame(
			array(
				'adaptor' => Library_Map::CACHE_POOLS['apcu'],
				'args'    => array( Cache_Backend::VERDICTS, 600 ),
			),
			$metadata['verify_cache'] ?? null,
			'Library 2.33.0 accepts a named pool for verification too, so it follows the setting.'
		);
	}

	/**
	 * A named directory compiles to an absolute path, and is created.
	 *
	 * The library carries on uncached when a cache directory is unwritable, so
	 * a directory that was only assumed would be 600 ms a request, reported
	 * only in the log.
	 */
	public function test_a_named_directory_compiles_to_an_absolute_path(): void {
		$metadata = $this->compiled_rule_metadata(
			array(
				'backend'   => 'filesystem',
				'directory' => self::DIRECTORY,
			)
		);

		$resolved = Plugin::instance()->paths()->resolve( self::DIRECTORY );

		$this->assertSame(
			array(
				'adaptor' => Library_Map::CACHE_POOLS['filesystem'],
				'args'    => array( Cache_Backend::AGENTS, 0, $resolved ),
			),
			$metadata['cache'] ?? null
		);
		$this->assertDirectoryExists( $resolved );
	}

	/**
	 * A rule that opts out of caching stays opted out, whatever the backend.
	 */
	public function test_a_rule_that_opts_out_stays_out(): void {
		$metadata = $this->compiled_rule_metadata( array( 'backend' => 'apcu' ), array( 'cache_detection' => false ) );

		$this->assertFalse( $metadata['cache'] ?? null );
		$this->assertSame( array(), Plugin::instance()->compiled()->cache_pool_paths() );
	}

	/**
	 * The object cache writes nothing into the file, and records where it belongs.
	 *
	 * It cannot be written down -- YAML carries no object -- so what the
	 * compile owes the runner is the paths.
	 */
	public function test_the_object_cache_is_not_compiled_but_its_paths_are_recorded(): void {
		$metadata = $this->compiled_rule_metadata( array( 'backend' => 'object_cache' ) );

		$this->assertArrayNotHasKey( 'cache', $metadata );
		$this->assertArrayNotHasKey( 'verify_cache', $metadata );
		$this->assertSame( array( '[plugins][0][metadata][cache]' ), Plugin::instance()->compiled()->cache_pool_paths() );
		$this->assertSame( array( '[plugins][0][metadata][verify_cache]' ), Plugin::instance()->compiled()->verify_cache_paths() );
	}

	/**
	 * Without a persistent object cache, nothing is handed over.
	 *
	 * WordPress's default object cache forgets everything at the end of the
	 * request. Handing it over would parse the corpus afresh every time; the
	 * library's file default is slower than a real object cache and far
	 * faster than that.
	 */
	public function test_a_non_persistent_object_cache_is_not_handed_over(): void {
		$this->compiled_rule_metadata( array( 'backend' => 'object_cache' ) );

		wp_using_ext_object_cache( false );

		$this->assertSame( array(), Cache_Backend::overrides() );
	}

	/**
	 * With a persistent one, it is handed over at every recorded path.
	 */
	public function test_a_persistent_object_cache_is_handed_over(): void {
		$this->compiled_rule_metadata( array( 'backend' => 'object_cache' ) );

		wp_using_ext_object_cache( true );

		$overrides = Cache_Backend::overrides();

		$this->assertSame( array( '[plugins][0][metadata][cache]', '[plugins][0][metadata][verify_cache]' ), array_keys( $overrides ) );
		$this->assertContainsOnlyInstancesOf( Object_Cache_Adapter::class, $overrides );
		$this->assertNotSame( $overrides['[plugins][0][metadata][cache]'], $overrides['[plugins][0][metadata][verify_cache]'], 'Corpus and verdicts are kept apart.' );
	}

	/**
	 * The library writes through a pool injected at the recorded path.
	 *
	 * The seam the object cache rests on. A recording pool stands in for the
	 * object cache, so what is proved is the path rather than WordPress's
	 * cache. Exception mode, because the library bypasses itself under the
	 * command line in every other mode.
	 */
	public function test_the_library_writes_through_the_pool_at_the_recorded_path(): void {
		$this->compiled_rule_metadata( array( 'backend' => 'object_cache' ) );

		$pool      = new ArrayAdapter();
		$overrides = array(
			'[global][mode]'       => 'exception',
			'[global][panic_file]' => '',
			'[storage][type]'      => Library_Map::STORAGE['memory'],
			'[storage][config]'    => array(),
		);

		foreach ( Plugin::instance()->compiled()->cache_pool_paths() as $path ) {
			$overrides[ $path ] = $pool;
		}

		$request = Request::create( '/', 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => '203.0.113.7' ) );
		$request->headers->set( 'User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );

		try {
			Firewall::create( array( Plugin::instance()->paths()->compiled_file() ), $overrides )->evaluate( $request );
		} catch ( \Throwable $e ) {
			$this->assertStringNotContainsString( 'cache', strtolower( $e->getMessage() ) );
		}

		$this->assertNotSame( array(), $pool->getValues(), 'Detection ran and nothing was written to the injected pool.' );
	}

	/**
	 * The object cache pool stores, misses, deletes and clears.
	 */
	public function test_the_object_cache_pool_round_trips(): void {
		$pool = new Object_Cache_Adapter( 'basic_firewall_test' );

		$this->assertFalse( $pool->getItem( 'absent' )->isHit() );
		$this->assertNull( $pool->getItem( 'absent' )->get(), 'A miss carries no value.' );

		$pool->save( $pool->getItem( 'present' )->set( array( 'bot' => true ) ) );
		$this->assertSame( array( 'bot' => true ), $pool->getItem( 'present' )->get() );

		$pool->deleteItem( 'present' );
		$this->assertFalse( $pool->getItem( 'present' )->isHit() );

		$pool->save( $pool->getItem( 'cleared' )->set( 1 ) );
		$pool->clear();
		$this->assertFalse( ( new Object_Cache_Adapter( 'basic_firewall_test' ) )->getItem( 'cleared' )->isHit(), 'A clear reaches a pool built afterwards.' );
	}

	/**
	 * Two namespaces in the one group do not see each other.
	 */
	public function test_namespaces_keep_the_corpus_and_the_verdicts_apart(): void {
		$agents   = new Object_Cache_Adapter( Cache_Backend::AGENTS );
		$verdicts = new Object_Cache_Adapter( Cache_Backend::VERDICTS );

		$agents->save( $agents->getItem( 'shared' )->set( 'agent' ) );
		$verdicts->save( $verdicts->getItem( 'shared' )->set( 'verdict' ) );

		$verdicts->clear();

		$this->assertSame( 'agent', $agents->getItem( 'shared' )->get(), 'Clearing verdicts discarded the corpus.' );
		$agents->clear();
	}

	/**
	 * Clearing empties the object cache pools.
	 */
	public function test_clearing_empties_the_object_cache(): void {
		$agents = new Object_Cache_Adapter( Cache_Backend::AGENTS );
		$agents->save( $agents->getItem( 'parsed' )->set( 'corpus' ) );

		$cleared = ( new Cache_Clearer() )->clear();

		$this->assertContains( 'object_cache', $cleared );
		$this->assertFalse( ( new Object_Cache_Adapter( Cache_Backend::AGENTS ) )->getItem( 'parsed' )->isHit() );
	}

	/**
	 * Clearing removes cached files and leaves the durable ones.
	 *
	 * The parsed configuration is what the firewall reads to know its rules,
	 * and without the list bodies every rule built on a list matches nothing
	 * until cron fetches them again.
	 */
	public function test_clearing_removes_cached_files_and_keeps_the_durable_ones(): void {
		$library = Plugin::instance()->paths()->library_cache_dir();
		$class   = Library_Map::CACHE_POOLS['filesystem'];
		$pool    = new $class( 'device-detector', 0, $library );
		$pool->save( $pool->getItem( 'corpus' )->set( 'parsed' ) );

		$sources = $library . '/sources';
		$fixture = $sources . '/test-cache-backend.json';
		wp_mkdir_p( $sources );
		file_put_contents( $fixture, '[]' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local fixture file.

		try {
			( new Cache_Clearer() )->clear();

			$this->assertFalse( ( new $class( 'device-detector', 0, $library ) )->getItem( 'corpus' )->isHit(), 'The corpus survived a clear.' );
			$this->assertFileExists( $fixture, 'A list body was deleted, so every rule built on it matches nothing until cron.' );
			$this->assertDirectoryExists( $library . '/compiled' );
		} finally {
			wp_delete_file( $fixture );
		}
	}

	/**
	 * The screen stores the cache settings.
	 */
	public function test_the_screen_stores_the_cache_settings(): void {
		$this->submit(
			array(
				'cache_backend'   => 'filesystem',
				'cache_directory' => ' ' . self::DIRECTORY . ' ',
				'cache_apcu_ttl'  => '600',
			)
		);

		$cache = (array) Plugin::instance()->settings()->get( 'cache' );

		$this->assertSame( 'filesystem', $cache['backend'] );
		$this->assertSame( self::DIRECTORY, $cache['directory'] );
		$this->assertSame( 600, $cache['apcu_ttl'] );
	}

	/**
	 * The object cache cannot be newly chosen where it is not persistent.
	 */
	public function test_a_non_persistent_object_cache_cannot_be_chosen(): void {
		wp_using_ext_object_cache( false );
		$this->given_settings( array( 'cache' => array( 'backend' => 'filesystem' ) ) );

		$this->submit( array( 'cache_backend' => 'object_cache' ) );

		$this->assertSame( 'filesystem', Plugin::instance()->settings()->get( 'cache.backend' ) );
	}

	/**
	 * A site already on the object cache keeps it when the drop-in goes.
	 *
	 * Saving anything else on the screen must not change a setting nobody
	 * touched.
	 */
	public function test_a_site_already_on_the_object_cache_keeps_it(): void {
		wp_using_ext_object_cache( false );
		$this->given_settings( array( 'cache' => array( 'backend' => 'object_cache' ) ) );

		$this->submit( array( 'cache_backend' => 'object_cache' ) );

		$this->assertSame( 'object_cache', Plugin::instance()->settings()->get( 'cache.backend' ) );
	}

	/**
	 * The screen's clear control clears, and saves nothing.
	 */
	public function test_the_clear_control_clears_and_saves_nothing(): void {
		$this->given_settings( array( 'cache' => array( 'apcu_ttl' => 900 ) ) );

		$agents = new Object_Cache_Adapter( Cache_Backend::AGENTS );
		$agents->save( $agents->getItem( 'parsed' )->set( 'corpus' ) );

		$this->submit(
			array(
				'storage_action' => 'clear_cache',
				'cache_apcu_ttl' => '60',
			)
		);

		$this->assertFalse( ( new Object_Cache_Adapter( Cache_Backend::AGENTS ) )->getItem( 'parsed' )->isHit() );
		$this->assertSame( 900, Plugin::instance()->settings()->get( 'cache.apcu_ttl' ), 'Clearing applied a half-edited form.' );
	}

	/**
	 * Site Health says when the object cache is chosen and not there.
	 */
	public function test_site_health_reports_a_missing_object_cache(): void {
		wp_using_ext_object_cache( false );
		$this->given_settings( array( 'cache' => array( 'backend' => 'object_cache' ) ) );

		$this->assertSame( 'recommended', Site_Health::check( 'cache' )['status'] );
	}

	/**
	 * Site Health calls APCu without APCu critical.
	 *
	 * Unlike the object cache, it does not fall back to files: the library
	 * cannot build the pool the compiled file names and runs detection
	 * uncached.
	 */
	public function test_site_health_reports_missing_apcu_as_critical(): void {
		if ( Cache_Backend::has_apcu() ) {
			$this->markTestSkipped( 'APCu is enabled in this PHP.' );
		}

		$this->given_settings( array( 'cache' => array( 'backend' => 'apcu' ) ) );

		$this->assertSame( 'critical', Site_Health::check( 'cache' )['status'] );
	}

	/**
	 * With APCu enabled, the library fills it from the compiled file alone.
	 *
	 * The compile-time assertions above prove the class name and arguments
	 * are written; this proves the library can build the pool from them and
	 * write through it -- which needs APCu in the CLI, and so had never run.
	 * Exception mode, because the library bypasses itself under the command
	 * line in every other mode.
	 */
	public function test_the_library_writes_to_apcu_from_the_compiled_file(): void {
		$this->requires_apcu();

		$this->compiled_rule_metadata( array( 'backend' => 'apcu' ) );
		( new Cache_Clearer() )->clear();

		$this->assertSame( array(), $this->apcu_keys( Cache_Backend::AGENTS ), 'Clearing left APCu entries behind, so the assertion below would prove nothing.' );

		$request = Request::create( '/', 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => '203.0.113.7' ) );
		$request->headers->set( 'User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );

		try {
			Firewall::create(
				array( Plugin::instance()->paths()->compiled_file() ),
				array(
					'[global][mode]'       => 'exception',
					'[global][panic_file]' => '',
					'[storage][type]'      => Library_Map::STORAGE['memory'],
					'[storage][config]'    => array(),
				)
			)->evaluate( $request );
		} catch ( \Throwable $e ) {
			$this->assertStringNotContainsString( 'cache', strtolower( $e->getMessage() ) );
		}

		$this->assertNotSame( array(), $this->apcu_keys( Cache_Backend::AGENTS ), 'Detection ran on the APCu backend and nothing reached APCu.' );

		// And the Clear control empties it again.
		$this->assertContains( 'apcu', ( new Cache_Clearer() )->clear() );
		$this->assertSame( array(), $this->apcu_keys( Cache_Backend::AGENTS ), 'Clearing the cache left the APCu entries.' );
	}

	/**
	 * With APCu enabled, choosing it is not reported as a problem.
	 *
	 * The counterpart of the test above it, which can only run where APCu is
	 * absent; CI runs each in a different job.
	 */
	public function test_site_health_accepts_apcu_where_it_is_enabled(): void {
		$this->requires_apcu();

		$this->given_settings( array( 'cache' => array( 'backend' => 'apcu' ) ) );

		$this->assertNotSame( 'critical', Site_Health::check( 'cache' )['status'] );
	}

	/**
	 * The APCu keys under a namespace.
	 *
	 * @param string $name_space Pool namespace.
	 *
	 * @return list<string>
	 */
	private function apcu_keys( string $name_space ): array {
		$keys = array();

		foreach ( new \APCUIterator( '/^' . preg_quote( $name_space, '/' ) . ':/', APC_ITER_KEY ) as $entry ) {
			$keys[] = (string) $entry['key'];
		}

		return $keys;
	}

	/**
	 * Store cache settings and a user agent rule, compile, and read its metadata.
	 *
	 * @param array<string, mixed> $cache    Cache settings.
	 * @param array<string, mixed> $settings Rule settings over the defaults.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled_rule_metadata( array $cache, array $settings = array() ): array {
		$this->given_settings(
			array(
				'enabled' => true,
				'cache'   => $cache,
			)
		);
		Plugin::instance()->settings()->set( 'rules', array( $this->rule( $settings ) ) );
		Plugin::instance()->compiled()->rebuild();

		$compiled = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		return is_array( $compiled ) ? (array) ( $compiled['plugins'][0]['metadata'] ?? array() ) : array();
	}

	/**
	 * A user agent rule that verifies crawlers, so it caches both ways.
	 *
	 * @param array<string, mixed> $settings Settings over the defaults.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $settings = array() ): array {
		return array(
			'id'              => 'crawlers',
			'type'            => 'user_agent',
			'label'           => 'Known crawlers',
			'enabled'         => true,
			'observe'         => false,
			'response'        => 'allow',
			'weight'          => 0,
			'status_code'     => 0,
			'record'          => 'default',
			'redirect_to'     => '',
			'redirect_status' => 302,
			'mark_as'         => '',
			'mark_header'     => '',
			'expiration'      => 0,
			'settings'        => $settings + array(
				'match_type'      => 'any',
				'sources'         => array(),
				'cache_detection' => true,
				'bot_source'      => 'curated',
				'verify'          => true,
				'verify_suffixes' => array( '.googlebot.com' ),
				'conditions'      => array(
					array(
						'variable' => 'bot',
						'operator' => 'equals',
						'value'    => 'true',
					),
				),
			),
		);
	}

	/**
	 * Post the storage form.
	 *
	 * @param array<string, string> $fields Posted fields.
	 */
	private function submit( array $fields ): void {
		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 1,
				'fields' => 'ID',
			)
		);

		if ( array() === $admins ) {
			$this->markTestSkipped( 'The site has no administrator to act as.' );
		}

		wp_set_current_user( (int) $admins[0] );

		$_GET  = array();
		$_POST = $fields + array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-storage' ),
			'backend'              => 'file',
			'storage_file'         => 'blocked.data',
			'offense_file'         => '',
			'storage_table'        => 'basic_firewall_blocked',
			'offenses_table'       => 'basic_firewall_offenses',
			'connection_source'    => 'wordpress',
			'cache_backend'        => 'filesystem',
			'cache_directory'      => '',
			'cache_apcu_ttl'       => '86400',
		);

		add_filter(
			'wp_redirect',
			static function (): void {
				throw new \RuntimeException( 'redirected' );
			}
		);

		try {
			( new Storage_Screen() )->handle();
		} catch ( \RuntimeException $e ) {
			$this->assertSame( 'redirected', $e->getMessage() );
		}

		Plugin::instance()->settings()->flush();
	}

	/**
	 * Remove a fixture directory and everything in it.
	 *
	 * @param string $directory Directory.
	 */
	private function remove_tree( string $directory ): void {
		if ( ! is_dir( $directory ) ) {
			return;
		}

		$entries = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $directory, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);

		foreach ( $entries as $entry ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- removing a local test fixture.
			$entry->isDir() ? rmdir( $entry->getPathname() ) : unlink( $entry->getPathname() );
		}

		rmdir( $directory ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- removing a local test fixture.
	}
}
