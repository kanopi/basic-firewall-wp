<?php
/**
 * How stored paths resolve.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Support\Paths;
use PHPUnit\Framework\TestCase;

/**
 * Pins how a stored path becomes a real one.
 *
 * @covers \Kanopi\BasicFirewall\Support\Paths
 */
final class PathsTest extends TestCase {

	/**
	 * An absolute path is somebody's deliberate choice and is left alone.
	 *
	 * @dataProvider absolute_paths
	 *
	 * @param string $path What was stored.
	 */
	public function test_absolute_paths_are_recognised( string $path ): void {
		$this->assertTrue(
			Paths::is_absolute( $path ),
			sprintf( '%s should be treated as absolute.', $path )
		);
	}

	/**
	 * Spellings of an absolute path, on both families of platform.
	 *
	 * The Windows ones matter: a plugin that treated `C:\firewall\blocked.data`
	 * as relative would quietly write it inside the uploads directory, under a
	 * filename containing a colon.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function absolute_paths(): array {
		return array(
			'posix'         => array( '/var/private/blocked.data' ),
			'posix root'    => array( '/' ),
			'windows drive' => array( 'C:\\firewall\\blocked.data' ),
			'windows slash' => array( 'C:/firewall/blocked.data' ),
			'unc'           => array( '\\\\server\\share\\blocked.data' ),
		);
	}

	/**
	 * A relative path is relative, whatever it contains.
	 *
	 * @dataProvider relative_paths
	 *
	 * @param string $path What was stored.
	 */
	public function test_relative_paths_are_recognised( string $path ): void {
		$this->assertFalse(
			Paths::is_absolute( $path ),
			sprintf( '%s should be treated as relative.', $path )
		);
	}

	/**
	 * Spellings of a relative path.
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function relative_paths(): array {
		return array(
			'bare file'   => array( 'blocked.data' ),
			'nested'      => array( 'logs/firewall.log' ),
			'dot slash'   => array( './blocked.data' ),
			'empty'       => array( '' ),
			'colon later' => array( 'logs/firewall:1.log' ),
		);
	}

	/**
	 * The Drupal scheme is not written, but is still understood.
	 *
	 * `private://` is a registered stream wrapper in Drupal and nothing at all
	 * in WordPress. It was carried across from the module, and dropping it is
	 * the point of this change -- but a site upgrading from a build that stored
	 * it must not suddenly resolve its block list to a different file and lose
	 * every block it had.
	 */
	public function test_the_legacy_drupal_scheme_still_resolves(): void {
		$this->assertSame(
			'private://',
			Paths::LEGACY_SCHEME,
			'The legacy scheme constant is what Paths::resolve() and the upgrade routine both key on.'
		);

		$this->assertFalse(
			Paths::is_absolute( Paths::LEGACY_SCHEME . 'blocked.data' ),
			'A legacy path must not be mistaken for an absolute one, or it would resolve outside the private directory.'
		);
	}
}
