<?php
/**
 * A rebuild that fails leaves the file in force described as it was.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;

/**
 * The compiled file on disk is what the runtime reads, failed rebuild or not.
 *
 * A rebuild that could not write a new file used to record empty injection
 * paths and delete the connection-paths sidecar anyway. The old file stayed
 * in force, now with nothing telling either path where the database
 * credentials belong -- so database-backed storage failed open until somebody
 * fixed whatever broke the rebuild.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache
 */
final class RebuildFailureTest extends Settings_Snapshot {

	/**
	 * The filter that sends the private directory somewhere unwritable.
	 *
	 * @var callable|null
	 */
	private $unwritable = null;

	/**
	 * Take the filter off and point the paths back at the real directory.
	 */
	protected function tearDown(): void {
		if ( null !== $this->unwritable ) {
			remove_filter( 'basic_firewall_private_path', $this->unwritable );
		}

		Plugin::instance()->paths()->reset();

		parent::tearDown();
	}

	/**
	 * The injection paths and their sidecar survive a rebuild that failed.
	 */
	public function test_a_failed_rebuild_keeps_the_injection_paths(): void {
		$this->given_settings(
			array(
				'storage' => array(
					'backend'  => 'database',
					'database' => array( 'connection_source' => 'wordpress' ),
				),
			)
		);

		$cache  = Plugin::instance()->compiled();
		$result = $cache->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile: ' . implode( ' ', $result['problems'] ) );

		$paths   = $cache->connection_paths();
		$sidecar = Plugin::instance()->paths()->connection_paths_file();

		$this->assertNotSame( array(), $paths, 'Database storage recorded no injection path, so this test proves nothing.' );
		$this->assertFileExists( $sidecar );

		// Somewhere no directory can be made: under a regular file.
		$this->unwritable = static fn (): string => ABSPATH . 'wp-load.php/basic-firewall-private';

		add_filter( 'basic_firewall_private_path', $this->unwritable );
		Plugin::instance()->paths()->reset();

		$failed = $cache->rebuild();

		$this->assertFalse( $failed['written'], 'The rebuild was expected to fail.' );

		remove_filter( 'basic_firewall_private_path', $this->unwritable );
		$this->unwritable = null;
		Plugin::instance()->paths()->reset();

		$this->assertSame( $paths, $cache->connection_paths(), 'A failed rebuild wiped the injection paths the file still in force needs.' );
		$this->assertFileExists( $sidecar, 'A failed rebuild removed the sidecar the wp-config.php path reads the same paths from.' );
		$this->assertFalse( (bool) ( $cache->meta()['written'] ?? true ), 'The failure is no longer reported.' );
		$this->assertNotSame( array(), $cache->meta()['problems'] ?? array() );
	}
}
