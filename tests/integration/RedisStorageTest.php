<?php
/**
 * Keeping the block list in Redis.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Screen\Storage_Screen;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Transfer\Exporter;
use Symfony\Component\Yaml\Yaml;

/**
 * The Redis block list: its shape, its credentials, and its absence.
 *
 * The shape is the whole risk, and it is not the shape the plugin already had.
 * Rate limit counters take flat `redis_host` and `redis_port` settings; the
 * block list takes its options nested under `config.redis`, spelled the way
 * `ext-redis` spells them. Reusing the familiar names produces a configuration
 * the backend ignores, so it connects to localhost while the screen says
 * otherwise -- and nothing reports it, because localhost usually answers.
 *
 * Nothing here connects to a server. Compilation is read from the compiled
 * file, and the screen is driven with Redis left unselected wherever a save
 * would otherwise make the block list screen open a connection.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Admin\Screen\Storage_Screen
 * @covers \Kanopi\BasicFirewall\Library_Capabilities
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class RedisStorageTest extends Settings_Snapshot {

	/**
	 * Request globals, put back after each test.
	 *
	 * @var array{get: array<mixed>, post: array<mixed>, user: int}
	 */
	private array $globals;

	/**
	 * Remember the request globals.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->globals = array(
			'get'  => $_GET, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'post' => $_POST, // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'user' => get_current_user_id(),
		);
	}

	/**
	 * Put them back, and drop any notices a screen queued.
	 */
	protected function tearDown(): void {
		delete_transient( 'basic_firewall_notices_' . get_current_user_id() );
		remove_all_filters( 'wp_redirect' );

		$_GET  = $this->globals['get'];
		$_POST = $this->globals['post'];
		wp_set_current_user( $this->globals['user'] );

		parent::tearDown();
	}

	/**
	 * The backend compiles to the nested shape the library reads.
	 */
	public function test_it_compiles_to_the_nested_shape(): void {
		$this->requires_the_class();

		$storage = $this->compiled_with(
			array(
				'host'   => 'redis.internal',
				'port'   => 6380,
				'prefix' => 'site1:',
			)
		);

		$this->assertSame( Library_Map::STORAGE['redis'], $storage['type'] ?? null );
		$this->assertSame(
			array(
				'host'   => 'redis.internal',
				'port'   => 6380,
				'prefix' => 'site1:',
			),
			$storage['config']['redis'] ?? null
		);
		$this->assertArrayHasKey( 'record_request', $storage['config'], 'What a record keeps applies to every backend.' );
	}

	/**
	 * The port is compiled as an integer.
	 *
	 * Written by hand or through WP-CLI it can arrive as a string, and
	 * `ext-redis` skips an option it cannot use rather than refusing it.
	 */
	public function test_the_port_is_compiled_as_an_integer(): void {
		$this->requires_the_class();

		$storage = $this->compiled_with( array( 'port' => '6380' ) );

		$this->assertSame( 6380, $storage['config']['redis']['port'] ?? null );
	}

	/**
	 * An empty prefix is derived from the site, never left to the library.
	 *
	 * The library's own default is one `firewall:` for everybody on the server.
	 */
	public function test_an_empty_prefix_is_derived_from_the_site(): void {
		$this->requires_the_class();

		$storage = $this->compiled_with( array( 'prefix' => '' ) );

		$this->assertSame( ( new Database_Credentials() )->block_list_key_prefix(), $storage['config']['redis']['prefix'] ?? null );

		if ( ! is_multisite() ) {
			$this->assertSame( 'firewall:', $storage['config']['redis']['prefix'] ?? null, 'A single site writes what the library would have.' );
		}
	}

	/**
	 * A password alone compiles to the ordinary requirepass form.
	 */
	public function test_a_password_alone_compiles_as_a_string(): void {
		$this->requires_the_class();

		$this->assertSame( 'hunter2', $this->compiled_with( array( 'password' => 'hunter2' ) )['config']['redis']['auth'] ?? null );
	}

	/**
	 * A username and password compile to the pair ACL authentication needs.
	 */
	public function test_a_username_and_password_compile_as_a_pair(): void {
		$this->requires_the_class();

		$storage = $this->compiled_with(
			array(
				'username' => 'firewall',
				'password' => 'hunter2',
			)
		);

		$this->assertSame( array( 'firewall', 'hunter2' ), $storage['config']['redis']['auth'] ?? null );
	}

	/**
	 * A username with no password is not written as a credential.
	 *
	 * The server would not accept it, and writing it would put something in
	 * the compiled file that reads like authentication and is not.
	 */
	public function test_a_username_without_a_password_writes_no_auth(): void {
		$this->requires_the_class();

		$this->assertArrayNotHasKey( 'auth', $this->compiled_with( array( 'username' => 'firewall' ) )['config']['redis'] );
	}

	/**
	 * A password is kept byte for byte, surrounding spaces included.
	 *
	 * Every other string in the settings is trimmed, which is right for a
	 * hostname and silently wrong for a credential somebody was issued.
	 */
	public function test_a_password_is_not_trimmed(): void {
		$this->requires_the_class();

		$this->assertSame( ' hunter2 ', $this->compiled_with( array( 'password' => ' hunter2 ' ) )['config']['redis']['auth'] ?? null );
		$this->assertSame( ' hunter2 ', Plugin::instance()->settings()->get( 'storage.redis.password' ) );
	}

	/**
	 * The password is stripped from an export and named; the username stays.
	 */
	public function test_the_password_is_stripped_from_an_export(): void {
		$this->given_settings(
			array(
				'storage' => array(
					'redis' => array(
						'username' => 'firewall',
						'password' => 'hunter2-redis',
					),
				),
			)
		);

		$export = ( new Exporter() )->export();

		$this->assertStringNotContainsString( 'hunter2-redis', ( new Exporter() )->to_yaml() );
		$this->assertContains( 'storage.redis.password', $export['redacted'] );
		$this->assertSame( 'firewall', $export['document']['storage']['redis']['username'] ?? null, 'The username is half a credential, not the secret half.' );
	}

	/**
	 * An environment token is not a secret and survives an export.
	 */
	public function test_an_environment_token_survives_an_export(): void {
		$this->given_settings(
			array( 'storage' => array( 'redis' => array( 'password' => '%env(REDIS_PASSWORD)%' ) ) )
		);

		$export = ( new Exporter() )->export();

		$this->assertSame( '%env(REDIS_PASSWORD)%', $export['document']['storage']['redis']['password'] ?? null );
		$this->assertNotContains( 'storage.redis.password', $export['redacted'] );
	}

	/**
	 * The backend is offered only where it could actually work.
	 */
	public function test_it_is_usable_only_with_both_the_class_and_the_extension(): void {
		$capabilities = new Library_Capabilities();

		$this->assertSame(
			$capabilities->has_redis_storage_class() && extension_loaded( 'redis' ),
			$capabilities->has_redis_storage()
		);
	}

	/**
	 * The screen stores the connection, and a blank password keeps the stored one.
	 *
	 * The backend is left on file: selecting Redis would have the block list
	 * screen connect to a host that is not there. The fields are stored
	 * whatever the backend is, which is what this exercises.
	 */
	public function test_the_screen_stores_the_connection_and_keeps_a_blank_password(): void {
		$this->requires_usable_redis();

		$this->given_settings( array( 'storage' => array( 'redis' => array( 'password' => 'stored-secret' ) ) ) );

		$this->submit(
			array(
				'backend'        => 'file',
				'redis_host'     => ' redis.internal ',
				'redis_port'     => '6380',
				'redis_prefix'   => 'site1:',
				'redis_username' => 'firewall',
				'redis_password' => '',
			)
		);

		$redis = (array) Plugin::instance()->settings()->get( 'storage.redis' );

		$this->assertSame( 'redis.internal', $redis['host'] );
		$this->assertSame( 6380, $redis['port'] );
		$this->assertSame( 'site1:', $redis['prefix'] );
		$this->assertSame( 'firewall', $redis['username'] );
		$this->assertSame( 'stored-secret', $redis['password'], 'A blank field means keep it: the stored password is never sent to the browser to be sent back.' );
	}

	/**
	 * A typed password is stored as typed, and the box removes it.
	 */
	public function test_the_screen_replaces_and_removes_the_password(): void {
		$this->requires_usable_redis();

		$this->submit( $this->redis_fields( array( 'redis_password' => ' new secret ' ) ) );
		$this->assertSame( ' new secret ', Plugin::instance()->settings()->get( 'storage.redis.password' ) );

		$this->submit( $this->redis_fields( array( 'redis_password_clear' => '1' ) ) );
		$this->assertSame( '', Plugin::instance()->settings()->get( 'storage.redis.password' ) );
	}

	/**
	 * A save with no Redis section leaves a stored connection alone.
	 *
	 * The section is not rendered on a server that can neither use Redis nor
	 * is already on it, and reading its absent fields as empty would blank the
	 * connection every time anything else on the screen was saved.
	 */
	public function test_a_save_without_the_section_keeps_the_connection(): void {
		$this->given_settings(
			array(
				'storage' => array(
					'redis' => array(
						'host'     => 'redis.internal',
						'password' => 'stored-secret',
					),
				),
			)
		);

		$this->submit( array( 'backend' => 'file' ) );

		$this->assertSame( 'redis.internal', Plugin::instance()->settings()->get( 'storage.redis.host' ) );
		$this->assertSame( 'stored-secret', Plugin::instance()->settings()->get( 'storage.redis.password' ) );
	}

	/**
	 * Without the extension, Redis cannot be newly chosen.
	 *
	 * Only reachable with a stale form or a hand-built request, because the
	 * option is not offered -- but storing it would leave a block list that
	 * keeps nothing.
	 */
	public function test_redis_cannot_be_chosen_without_the_extension(): void {
		$this->requires_missing_extension();

		$this->given_settings( array( 'storage' => array( 'backend' => 'file' ) ) );

		$this->submit( array( 'backend' => 'redis' ) );

		$this->assertSame( 'file', Plugin::instance()->settings()->get( 'storage.backend' ) );
	}

	/**
	 * A site already on Redis keeps it when the extension goes missing.
	 *
	 * Moving it to file storage on the next save of anything on the screen
	 * would move the block list without anybody deciding to.
	 */
	public function test_a_site_already_on_redis_keeps_it_without_the_extension(): void {
		$this->requires_missing_extension();

		$this->given_settings( array( 'storage' => array( 'backend' => 'redis' ) ) );

		$this->submit( $this->redis_fields( array( 'backend' => 'redis' ) ) );

		$this->assertSame( 'redis', Plugin::instance()->settings()->get( 'storage.backend' ) );
	}

	/**
	 * Site Health calls Redis without the extension critical, as it does memory.
	 */
	public function test_site_health_is_critical_without_the_extension(): void {
		$this->requires_the_class();
		$this->requires_missing_extension();

		$this->given_settings( array( 'storage' => array( 'backend' => 'redis' ) ) );

		$result = Site_Health::check( 'storage' );

		$this->assertSame( 'critical', $result['status'] );
		$this->assertStringContainsString( 'redis extension', $result['label'] );
	}

	/**
	 * Store Redis settings with the backend selected, and read the compiled storage.
	 *
	 * @param array<string, mixed> $redis Redis settings over the defaults.
	 *
	 * @return array<string, mixed>
	 */
	private function compiled_with( array $redis ): array {
		$this->given_settings(
			array(
				'storage' => array(
					'backend' => 'redis',
					'redis'   => $redis + array( 'host' => 'redis.internal' ),
				),
			)
		);

		Plugin::instance()->compiled()->rebuild();

		$compiled = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		return is_array( $compiled ) ? (array) ( $compiled['storage'] ?? array() ) : array();
	}

	/**
	 * The Redis fields as the screen renders them, backend left on file.
	 *
	 * @param array<string, string> $overrides Fields to change.
	 *
	 * @return array<string, string>
	 */
	private function redis_fields( array $overrides = array() ): array {
		return $overrides + array(
			'backend'        => 'file',
			'redis_host'     => '127.0.0.1',
			'redis_port'     => '6379',
			'redis_prefix'   => '',
			'redis_username' => '',
			'redis_password' => '',
		);
	}

	/**
	 * Post the storage form.
	 *
	 * @param array<string, string> $fields Posted fields.
	 */
	private function submit( array $fields ): void {
		$this->as_administrator();

		$_GET  = array();
		$_POST = $fields + array(
			'basic_firewall_nonce' => wp_create_nonce( 'basic_firewall_basic-firewall-storage' ),
			'storage_file'         => 'blocked.data',
			'offense_file'         => '',
			'storage_table'        => 'basic_firewall_blocked',
			'offenses_table'       => 'basic_firewall_offenses',
			'connection_source'    => 'wordpress',
		);

		// A save redirects and exits; stop it at the redirect.
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
	 * Act as an administrator, who holds the plugin's capability.
	 */
	private function as_administrator(): void {
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
	}

	/**
	 * Skip where the library has no Redis block list.
	 */
	private function requires_the_class(): void {
		if ( ! ( new Library_Capabilities() )->has_redis_storage_class() ) {
			$this->markTestSkipped( 'The installed library has no Redis block list.' );
		}
	}

	/**
	 * Skip unless Redis is offered on this server.
	 */
	private function requires_usable_redis(): void {
		if ( ! ( new Library_Capabilities() )->has_redis_storage() ) {
			$this->markTestSkipped( 'ext-redis is not loaded, so the Redis section is correctly absent.' );
		}
	}

	/**
	 * Skip where ext-redis is loaded, because it cannot be unloaded mid-run.
	 *
	 * Run these with the extension's ini left out of PHP_INI_SCAN_DIR.
	 */
	private function requires_missing_extension(): void {
		if ( extension_loaded( 'redis' ) ) {
			$this->markTestSkipped( 'ext-redis is loaded; run without it to exercise its absence.' );
		}
	}
}
