<?php
/**
 * Database block storage on the wp-config.php evaluation path.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;

/**
 * The early path can reach the database, and still keeps no credential on disk.
 *
 * The Drupal module documents database-backed storage as unusable before the
 * CMS loads. That is true of Drupal and false of WordPress: wp-config.php
 * defines DB_NAME, DB_USER, DB_PASSWORD and DB_HOST as plain constants above
 * the line the bootstrap is required from, so they are already in scope.
 *
 * Carrying the limitation over anyway would have cost every site that combines
 * a page cache with database storage a silent fail-open. These tests hold the
 * two halves of the replacement in place: the injection *paths* travel on disk
 * in a sidecar, because the option the normal path reads them from needs a
 * WordPress that does not exist yet; the *values* never do.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache
 * @covers \Kanopi\BasicFirewall\Database_Credentials
 */
final class EarlyPathStorageTest extends Settings_Snapshot {

	/**
	 * Load the bootstrap's functions, which are not autoloaded.
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';
	}

	/**
	 * Settings selecting database storage on WordPress's own connection.
	 *
	 * @return array<string, mixed>
	 */
	private function database_storage(): array {
		return array(
			'storage' => array(
				'backend'  => 'database',
				'database' => array(
					'storage_table'     => 'basic_firewall_blocked',
					'offenses_table'    => 'basic_firewall_offenses',
					'connection_source' => 'wordpress',
				),
			),
		);
	}

	/**
	 * The sidecar exists, and names where a connection belongs.
	 */
	public function test_the_sidecar_records_the_injection_paths(): void {
		$this->given_settings( $this->database_storage() );

		$rebuild = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $rebuild['written'], 'The compiled file was not written.' );

		$sidecar = Plugin::instance()->paths()->connection_paths_file();

		$this->assertFileIsReadable( $sidecar, 'The early path has no way to learn where credentials belong.' );

		$paths = json_decode( (string) file_get_contents( $sidecar ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test just wrote, not a remote URL.

		$this->assertIsArray( $paths );
		$this->assertNotEmpty( $paths, 'An empty sidecar injects nothing, which is a silent fail-open.' );
		$this->assertSame(
			Plugin::instance()->compiled()->connection_paths(),
			$paths,
			'The sidecar and the option disagree, so the two evaluation paths would configure storage differently.'
		);
	}

	/**
	 * The sidecar carries paths, never values.
	 *
	 * The whole point of runtime injection is that the compiled file cannot leak
	 * a password. A sidecar beside it that did would give the leak back.
	 */
	public function test_the_sidecar_carries_no_credential(): void {
		$this->given_settings( $this->database_storage() );

		Plugin::instance()->compiled()->rebuild();

		$contents = (string) file_get_contents( Plugin::instance()->paths()->connection_paths_file() ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file this test just wrote, not a remote URL.

		foreach ( array( 'password', 'dbname', 'user', 'driver' ) as $key ) {
			$this->assertStringNotContainsString(
				$key,
				$contents,
				sprintf( 'The sidecar looks like it carries connection values, not just paths (%s).', $key )
			);
		}

		if ( defined( 'DB_PASSWORD' ) && strlen( (string) DB_PASSWORD ) >= 8 ) {
			$this->assertStringNotContainsString( (string) DB_PASSWORD, $contents );
		}
	}

	/**
	 * Selecting a backend that needs no connection removes the sidecar.
	 *
	 * A stale sidecar would have the early path inject a connection into a
	 * config that has no storage block expecting one.
	 */
	public function test_switching_to_file_storage_removes_the_sidecar(): void {
		$this->given_settings( $this->database_storage() );
		Plugin::instance()->compiled()->rebuild();

		$sidecar = Plugin::instance()->paths()->connection_paths_file();
		$this->assertFileExists( $sidecar );

		$this->given_settings(
			array(
				'storage' => array(
					'backend' => 'file',
					'file'    => array(
						'storage_file' => 'blocked.data',
						'offense_file' => 'offenses.data',
					),
				),
			)
		);
		Plugin::instance()->compiled()->rebuild();

		$this->assertFileDoesNotExist( $sidecar, 'A stale sidecar survives a switch away from database storage.' );
	}

	/**
	 * The bootstrap builds the same overrides the runner does.
	 */
	public function test_the_bootstrap_injects_wordpress_credentials(): void {
		$this->given_settings( $this->database_storage() );
		Plugin::instance()->compiled()->rebuild();

		$options = array(
			'private_path' => Plugin::instance()->paths()->base(),
			'plugin_path'  => dirname( __DIR__, 2 ),
		);

		$overrides = basic_firewall_build_overrides( $options );

		$paths = Plugin::instance()->compiled()->connection_paths();

		$this->assertNotEmpty( $paths );

		foreach ( $paths as $path ) {
			$this->assertArrayHasKey(
				$path,
				$overrides,
				'The early path compiled a storage backend it then gave no connection to, which fails open on every request.'
			);

			$this->assertSame( DB_NAME, $overrides[ $path ]['dbname'] );
			$this->assertSame( DB_USER, $overrides[ $path ]['user'] );
			$this->assertArrayHasKey( 'driver', $overrides[ $path ] );
		}
	}

	/**
	 * An explicit connection in the options is not overwritten.
	 *
	 * A site pointing the firewall at a separate database passes one in, and
	 * silently replacing it with WordPress's own would write the block list
	 * somewhere the administrator did not choose.
	 */
	public function test_an_explicitly_supplied_connection_wins(): void {
		$this->given_settings( $this->database_storage() );
		Plugin::instance()->compiled()->rebuild();

		$paths = Plugin::instance()->compiled()->connection_paths();
		$mine  = array(
			'driver' => 'pdo_mysql',
			'dbname' => 'somewhere_else',
		);

		$overrides = basic_firewall_build_overrides(
			array(
				'private_path' => Plugin::instance()->paths()->base(),
				'plugin_path'  => dirname( __DIR__, 2 ),
				'overrides'    => array( $paths[0] => $mine ),
			)
		);

		$this->assertSame( $mine, $overrides[ $paths[0] ] );
	}
}
