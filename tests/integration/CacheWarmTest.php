<?php
/**
 * Building the agent corpus before a visitor has to.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Storage_Screen;
use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Cache\Cache_Warmer;
use Kanopi\BasicFirewall\Cache\Object_Cache_Adapter;
use Kanopi\BasicFirewall\Plugin;

/**
 * The warm: that it fills the cache the rules read, and only when there is one.
 *
 * Asserted on a named cache directory, because files are the one backend a
 * test can look inside: the corpus lands under the agent namespace there, or
 * it did not land.
 *
 * @covers \Kanopi\BasicFirewall\Cache\Cache_Warmer
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Storage_Screen
 */
final class CacheWarmTest extends Settings_Snapshot {

	/**
	 * A named cache directory, relative so it resolves inside the private directory.
	 */
	private const DIRECTORY = 'test-cache-warm';

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
			'external' => (bool) wp_using_ext_object_cache(),
		);

		wp_clear_scheduled_hook( Cache_Warmer::HOOK );
	}

	/**
	 * Put it back, and leave no event and no fixture directory behind.
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

		// The snapshot's own rebuild may have scheduled one.
		wp_clear_scheduled_hook( Cache_Warmer::HOOK );
	}

	/**
	 * With no user agent rule there is nothing to build, and it says so.
	 */
	public function test_no_user_agent_rule_warms_nothing(): void {
		$this->given_rules( array() );

		$report = ( new Cache_Warmer() )->warm();

		$this->assertSame( 0, $report['rules'] );
		$this->assertFalse( wp_next_scheduled( Cache_Warmer::HOOK ), 'A rebuild with nothing to warm scheduled a warm.' );
	}

	/**
	 * A caching rule is warmed into the backend the site chose.
	 */
	public function test_the_corpus_lands_in_the_chosen_backend(): void {
		$this->given_rules( array( $this->rule() ) );

		$report = ( new Cache_Warmer() )->warm();

		$this->assertSame( 1, $report['rules'] );
		$this->assertSame( 2, $report['agents'], 'A bot and a browser: a bot alone leaves the dear corpora cold.' );
		$this->assertNotSame( array(), $this->files_under( Cache_Backend::AGENTS ), 'Nothing was written where the rule caches.' );
	}

	/**
	 * A rule that turned its cache off is not warmed.
	 */
	public function test_a_rule_without_a_cache_is_left_alone(): void {
		$this->given_rules( array( $this->rule( array( 'cache_detection' => false ) ) ) );

		$this->assertSame( 0, ( new Cache_Warmer() )->warm()['rules'] );
	}

	/**
	 * A rebuild with something to warm schedules one warm, once.
	 *
	 * On cron rather than inline, so saving a form does not cost an
	 * administrator what this exists to spare a visitor.
	 */
	public function test_a_rebuild_schedules_one_warm(): void {
		$this->given_rules( array( $this->rule() ) );

		$first = wp_next_scheduled( Cache_Warmer::HOOK );

		$this->assertIsInt( $first );

		Plugin::instance()->compiled()->rebuild();

		$this->assertSame( $first, wp_next_scheduled( Cache_Warmer::HOOK ), 'A second rebuild scheduled a second warm.' );
	}

	/**
	 * The object cache is handed to the warm as it is to the runner.
	 */
	public function test_the_object_cache_is_handed_over_when_persistent(): void {
		$this->given_settings( array( 'cache' => array( 'backend' => 'object_cache' ) ) );

		wp_using_ext_object_cache( false );
		$this->assertNull( Cache_Backend::agent_pool() );

		wp_using_ext_object_cache( true );
		$this->assertInstanceOf( Object_Cache_Adapter::class, Cache_Backend::agent_pool() );
	}

	/**
	 * The screen's control builds the corpus, in the request that pressed it.
	 */
	public function test_the_build_control_warms(): void {
		$this->given_rules( array( $this->rule() ) );

		$this->submit( array( 'storage_action' => 'warm_cache' ) );

		$this->assertNotSame( array(), $this->files_under( Cache_Backend::AGENTS ) );
	}

	/**
	 * Install a rule set cached in the fixture directory, and compile it.
	 *
	 * @param list<array<string, mixed>> $rules Rules.
	 */
	private function given_rules( array $rules ): void {
		$this->given_settings(
			array(
				'enabled' => true,
				'cache'   => array(
					'backend'   => 'filesystem',
					'directory' => self::DIRECTORY,
				),
			)
		);
		wp_clear_scheduled_hook( Cache_Warmer::HOOK );

		Plugin::instance()->settings()->set( 'rules', $rules );
	}

	/**
	 * Files a pool namespace holds in the fixture directory.
	 *
	 * @param string $name_space Pool namespace.
	 *
	 * @return list<string>
	 */
	private function files_under( string $name_space ): array {
		$directory = Plugin::instance()->paths()->resolve( self::DIRECTORY ) . '/' . $name_space;

		if ( ! is_dir( $directory ) ) {
			return array();
		}

		$files = array();

		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $directory, \FilesystemIterator::SKIP_DOTS ) ) as $entry ) {
			if ( $entry->isFile() ) {
				$files[] = $entry->getPathname();
			}
		}

		return $files;
	}

	/**
	 * A user agent rule asking about every phase, so the warm has work to do.
	 *
	 * @param array<string, mixed> $settings Settings over the defaults.
	 *
	 * @return array<string, mixed>
	 */
	private function rule( array $settings = array() ): array {
		return array(
			'id'              => 'phones',
			'type'            => 'user_agent',
			'label'           => 'Phones',
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
				'verify'          => false,
				'verify_suffixes' => array(),
				'conditions'      => array(
					array(
						'variable' => 'device',
						'operator' => 'equals',
						'value'    => 'smartphone',
					),
				),
			),
		);
	}

	/**
	 * Post the storage screen's action form.
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
		$_POST = $fields + array( 'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-storage' ) );

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
