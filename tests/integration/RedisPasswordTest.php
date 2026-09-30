<?php
/**
 * Keeping the Redis password out of the compiled file.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Compiler\Config_Compiler;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Redis_Password;
use Kanopi\BasicFirewall\Runtime\Runner;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Component\Yaml\Yaml;

/**
 * BASIC_FIREWALL_REDIS_PASSWORD, injected on both paths (#48).
 *
 * The block list on Redis and a rate limit's counters on Redis both wrote the
 * password into the compiled file, under uploads. With the constant defined the
 * file holds none, and both evaluation paths hand the library the password as a
 * runtime override at the paths the compiler recorded.
 *
 * A constant cannot be undefined, so the constant is simulated on the plugin
 * side (Redis_Password::simulate()) and passed as the bootstrap's
 * `redis_password` option -- the option its default reads the constant into.
 *
 * Nothing here reaches a server unless BASIC_FIREWALL_TEST_REDIS names one
 * (`host` or `host:port`, with BASIC_FIREWALL_TEST_REDIS_PASSWORD).
 *
 * @covers \Kanopi\BasicFirewall\Redis_Password
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class RedisPasswordTest extends Settings_Snapshot {

	private const STORED   = 'STORED-REDIS-PASS-8f3a';
	private const COUNTERS = 'COUNTER-REDIS-PASS-1d7c';
	private const CONSTANT = 'CONSTANT-REDIS-PASS-5e2b';

	/**
	 * Load the bootstrap's functions, which are not autoloaded.
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';
	}

	/**
	 * Skip where the library has no Redis block list.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! ( new Library_Capabilities() )->has_redis_storage_class() ) {
			$this->markTestSkipped( 'The installed library has no Redis block list.' );
		}
	}

	/**
	 * Go back to reading the real constant, before the snapshot's rebuild.
	 */
	protected function tearDown(): void {
		Redis_Password::simulate( null, true );
		putenv( 'BFW_TEST_REDIS_PASSWORD' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- undoing what the test set.

		parent::tearDown();
	}

	/**
	 * With the constant, the compiled file holds no Redis password at all.
	 */
	public function test_with_the_constant_the_compiled_file_holds_no_password(): void {
		Redis_Password::simulate( self::CONSTANT );

		$compiled = $this->compile( self::STORED, self::COUNTERS );
		$contents = (string) Plugin::instance()->compiled()->contents();

		$this->assertStringNotContainsString( self::STORED, $contents );
		$this->assertStringNotContainsString( self::COUNTERS, $contents );
		$this->assertStringNotContainsString( self::CONSTANT, $contents );
		$this->assertArrayNotHasKey( 'auth', $compiled['storage']['config']['redis'] );
		$this->assertArrayNotHasKey( 'auth', $this->counters( $compiled )['config']['redis'] );

		foreach ( (array) glob( Plugin::instance()->paths()->base() . '/*.json' ) as $sidecar ) {
			$this->assertStringNotContainsString( self::CONSTANT, (string) file_get_contents( $sidecar ), basename( $sidecar ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test just wrote.
		}
	}

	/**
	 * Both Redis uses are recorded, with the block list's ACL username.
	 */
	public function test_both_connections_are_recorded(): void {
		Redis_Password::simulate( self::CONSTANT );

		$compiled = $this->compile( self::STORED, self::COUNTERS, 'fw-user' );
		$paths    = Plugin::instance()->compiled()->redis_auth_paths();
		$index    = $this->counters_index( $compiled );

		$this->assertSame(
			array(
				'[storage][config][redis][auth]' => 'fw-user',
				sprintf( '[plugins][%d][metadata][storage][config][redis][auth]', $index ) => '',
			),
			$paths
		);

		$sidecar = json_decode( (string) file_get_contents( Plugin::instance()->paths()->redis_auth_paths_file() ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test just wrote.

		$this->assertSame( $paths, $sidecar, 'The wp-config.php path would inject somewhere else.' );
	}

	/**
	 * The runner hands the library the constant at both connections.
	 */
	public function test_the_runner_injects_the_constant(): void {
		Redis_Password::simulate( self::CONSTANT );

		$compiled  = $this->compile( self::STORED, self::COUNTERS, 'fw-user' );
		$effective = $this->with_overrides( $compiled, $this->runner_overrides() );

		$this->assertSame( array( 'fw-user', self::CONSTANT ), $effective['storage']['config']['redis']['auth'] );
		$this->assertSame( self::CONSTANT, $this->counters( $effective )['config']['redis']['auth'] );
	}

	/**
	 * The wp-config.php path hands the library the same, from the constant alone.
	 */
	public function test_the_bootstrap_injects_the_constant(): void {
		Redis_Password::simulate( self::CONSTANT );

		$compiled  = $this->compile( self::STORED, self::COUNTERS, 'fw-user' );
		$overrides = basic_firewall_build_overrides(
			array(
				'private_path'   => Plugin::instance()->paths()->base(),
				'plugin_path'    => dirname( __DIR__, 2 ),
				'redis_password' => self::CONSTANT,
			)
		);

		$effective = $this->with_overrides( $compiled, $overrides );

		$this->assertSame( array( 'fw-user', self::CONSTANT ), $effective['storage']['config']['redis']['auth'] );
		$this->assertSame( self::CONSTANT, $this->counters( $effective )['config']['redis']['auth'] );

		// And the two paths agree.
		$runner = $this->runner_overrides();

		foreach ( Plugin::instance()->compiled()->redis_auth_paths() as $path => $username ) {
			$this->assertSame( $runner[ $path ] ?? null, $overrides[ $path ] ?? null, $path );
		}
	}

	/**
	 * Without the constant, neither path injects anything, and the file is used as written.
	 */
	public function test_without_the_constant_nothing_is_injected(): void {
		$this->compile( self::STORED, self::COUNTERS );

		$overrides = basic_firewall_build_overrides(
			array(
				'private_path'   => Plugin::instance()->paths()->base(),
				'plugin_path'    => dirname( __DIR__, 2 ),
				'redis_password' => null,
			)
		);

		foreach ( array_keys( Plugin::instance()->compiled()->redis_auth_paths() ) as $path ) {
			$this->assertArrayNotHasKey( $path, $overrides );
			$this->assertArrayNotHasKey( $path, $this->runner_overrides() );
		}
	}

	/**
	 * A literal password is still written, and Site Health recommends a better source.
	 */
	public function test_a_literal_password_is_written_and_recommended_against(): void {
		$compiled = $this->compile( self::STORED, self::COUNTERS );

		$this->assertSame( self::STORED, $compiled['storage']['config']['redis']['auth'], 'The literal case stopped working.' );
		$this->assertSame( self::COUNTERS, $this->counters( $compiled )['config']['redis']['auth'] );

		$result = Site_Health::check( 'redis_secret' );

		$this->assertSame( 'recommended', $result['status'] );
		$this->assertStringContainsString( 'plain text', $result['label'] );
		$this->assertStringContainsString( Redis_Password::CONSTANT, $result['description'] );
		$this->assertStringNotContainsString( self::STORED, $result['description'] );
	}

	/**
	 * A token stays a token in the compiled file, and is not reported.
	 */
	public function test_an_environment_token_stays_a_token(): void {
		$compiled = $this->compile( '%env(BFW_TEST_REDIS_PASSWORD)%', '%env(BFW_TEST_REDIS_PASSWORD)%' );

		$this->assertSame( '%env(BFW_TEST_REDIS_PASSWORD)%', $compiled['storage']['config']['redis']['auth'] );
		$this->assertSame( '%env(BFW_TEST_REDIS_PASSWORD)%', $this->counters( $compiled )['config']['redis']['auth'] );
		$this->assertSame( 'good', Site_Health::check( 'redis_secret' )['status'] );
	}

	/**
	 * A connection opened directly resolves the token, or takes the constant.
	 */
	public function test_a_live_connection_resolves_the_password(): void {
		putenv( 'BFW_TEST_REDIS_PASSWORD=from-the-environment' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- the environment is what a token reads.

		$token = array(
			'host'     => 'redis.internal',
			'password' => '%env(BFW_TEST_REDIS_PASSWORD)%',
		);

		$this->assertSame( 'from-the-environment', Config_Compiler::redis_storage_options( $token, true )['auth'] ?? null );
		$this->assertSame( '%env(BFW_TEST_REDIS_PASSWORD)%', Config_Compiler::redis_storage_options( $token )['auth'] ?? null, 'Compiling must keep the token.' );

		Redis_Password::simulate( self::CONSTANT );

		$this->assertSame( self::CONSTANT, Config_Compiler::redis_storage_options( array( 'host' => 'redis.internal' ), true )['auth'] ?? null );
	}

	/**
	 * With the constant, Site Health says so -- and flags a file written before it.
	 */
	public function test_site_health_follows_the_constant(): void {
		$this->compile( self::STORED, self::COUNTERS );

		Redis_Password::simulate( self::CONSTANT );

		$this->assertSame( 'recommended', Site_Health::check( 'redis_secret' )['status'], 'A file written before the constant still holds the password.' );

		Plugin::instance()->compiled()->rebuild();

		$this->assertSame( 'good', Site_Health::check( 'redis_secret' )['status'] );

		// The constant removed, the file left: no password anywhere.
		Redis_Password::simulate( null, true );

		if ( ! Redis_Password::is_overridden() ) {
			$this->assertSame( 'critical', Site_Health::check( 'redis_secret' )['status'] );
		}
	}

	/**
	 * Against a real server, when one is named: the injected password authenticates.
	 */
	public function test_a_live_server_accepts_the_injected_password(): void {
		$server = (string) getenv( 'BASIC_FIREWALL_TEST_REDIS' );

		if ( '' === $server || ! extension_loaded( 'redis' ) ) {
			$this->markTestSkipped( 'Set BASIC_FIREWALL_TEST_REDIS (and BASIC_FIREWALL_TEST_REDIS_PASSWORD), with ext-redis loaded, to run against a server.' );
		}

		$parts    = explode( ':', $server, 2 );
		$password = (string) getenv( 'BASIC_FIREWALL_TEST_REDIS_PASSWORD' );

		Redis_Password::simulate( $password );

		$this->given_settings(
			array(
				'storage' => array(
					'backend' => 'redis',
					'redis'   => array(
						'host'     => $parts[0],
						'port'     => (int) ( $parts[1] ?? 6379 ),
						'password' => 'wrong-on-purpose',
						'prefix'   => 'bfw-test:',
					),
				),
			)
		);

		Plugin::instance()->compiled()->rebuild();

		$compiled  = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );
		$effective = $this->with_overrides( $compiled, $this->runner_overrides() );
		$class     = Library_Map::STORAGE['redis'];
		$storage   = new $class( $effective['storage']['config'] );

		$this->assertTrue( $storage->set( 'bfw-password-probe', array( 'ok' => true ), 30 ), 'The server refused the injected password.' );
		$this->assertTrue( $storage->exists( 'bfw-password-probe' ) );

		$storage->delete( 'bfw-password-probe' );
	}

	/**
	 * Compile a block list and a rate limit, both on Redis.
	 *
	 * @param string $stored   The block list's stored password.
	 * @param string $counters The rate limit's stored password.
	 * @param string $username The block list's ACL username.
	 *
	 * @return array<string, mixed> The compiled file, parsed.
	 */
	private function compile( string $stored, string $counters, string $username = '' ): array {
		$this->given_settings(
			array(
				'storage' => array(
					'backend' => 'redis',
					'redis'   => array(
						'host'     => 'redis.internal',
						'username' => $username,
						'password' => $stored,
					),
				),
				'rules'   => array(
					array(
						'id'       => 'redis-counted',
						'type'     => 'rate_limit',
						'label'    => 'Counted in Redis',
						'enabled'  => true,
						'response' => 'block',
						'weight'   => 30,
						'settings' => array(
							'paths'   => array( '/wp-login.php 20 60' ),
							'storage' => array(
								'backend'        => 'redis',
								'redis_host'     => 'redis.internal',
								'redis_password' => $counters,
							),
						),
					),
				),
			)
		);

		$rebuild = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $rebuild['written'], implode( "\n", $rebuild['problems'] ) );

		$compiled = Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		$this->assertIsArray( $compiled );

		return $compiled;
	}

	/**
	 * The rate limit's plugin index in a compiled tree.
	 *
	 * @param array<string, mixed> $compiled The compiled tree.
	 */
	private function counters_index( array $compiled ): int {
		foreach ( (array) ( $compiled['plugins'] ?? array() ) as $index => $plugin ) {
			if ( is_array( $plugin['metadata']['storage']['config']['redis'] ?? null ) ) {
				return (int) $index;
			}
		}

		$this->fail( 'No rate limit kept its counters in Redis.' );
	}

	/**
	 * The rate limit's storage in a compiled tree.
	 *
	 * @param array<string, mixed> $compiled The compiled tree.
	 *
	 * @return array<string, mixed>
	 */
	private function counters( array $compiled ): array {
		return $compiled['plugins'][ $this->counters_index( $compiled ) ]['metadata']['storage'];
	}

	/**
	 * The overrides the runner hands the library.
	 *
	 * @return array<string, mixed>
	 */
	private function runner_overrides(): array {
		$method = new \ReflectionMethod( Runner::class, 'overrides' );
		$method->setAccessible( true );

		return (array) $method->invoke( Plugin::instance()->runner() );
	}

	/**
	 * A compiled tree with overrides applied, as the library applies them.
	 *
	 * @param array<string, mixed> $compiled  The compiled tree.
	 * @param array<string, mixed> $overrides Property-access path => value.
	 *
	 * @return array<string, mixed>
	 */
	private function with_overrides( array $compiled, array $overrides ): array {
		$accessor = PropertyAccess::createPropertyAccessor();

		foreach ( $overrides as $path => $value ) {
			if ( is_object( $value ) ) {
				continue;
			}

			$accessor->setValue( $compiled, (string) $path, $value );
		}

		return $compiled;
	}
}
