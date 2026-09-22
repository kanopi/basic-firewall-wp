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

	/**
	 * What gets written into the compiled file.
	 *
	 * @dataProvider portable_paths
	 *
	 * @param string $stored   What the administrator typed.
	 * @param string $expected What belongs in the compiled document.
	 * @param string $because  Why.
	 */
	public function test_portable_keeps_what_was_typed( string $stored, string $expected, string $because ): void {
		$this->assertSame( $expected, ( new Paths() )->portable( $stored ), $because );
	}

	/**
	 * Every shape a stored path arrives in.
	 *
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function portable_paths(): array {
		return array(
			'a bare filename stays relative'   => array(
				'blocked.data',
				'blocked.data',
				'The library resolves this against the directory holding the compiled file, which is where an absolute path would have pointed anyway -- so resolving it here only replaced what the administrator typed with something they did not.',
			),
			'a subdirectory stays relative'    => array(
				'logs/firewall.log',
				'logs/firewall.log',
				'Nested relative paths resolve the same way and must survive intact.',
			),
			'an absolute path is untouched'    => array(
				'/srv/firewall/blocked.data',
				'/srv/firewall/blocked.data',
				'Somebody who typed an absolute path chose it deliberately; the library leaves absolute values alone and so must this.',
			),
			'a stream wrapper is untouched'    => array(
				'php://stdout',
				'php://stdout',
				'A containerised host logs to stdout. Split on its slashes this became php:/stdout inside the private directory -- a directory named "php:" holding a file nobody reads.',
			),
			'parent traversal is stripped'     => array(
				'../../wp-config.php',
				'wp-config.php',
				'A relative path is handed onward for the library to resolve, so it has to be unable to climb out of whatever it is resolved against. This arrives from an imported document as readily as from a form.',
			),
			'traversal mid-path is stripped'   => array(
				'./x/../../../etc/passwd',
				'x/etc/passwd',
				'Traversal has to be stripped wherever it appears, not only at the front.',
			),
			'the legacy scheme is dropped'     => array(
				Paths::LEGACY_SCHEME . 'blocked.data',
				'blocked.data',
				'private:// is Drupal\'s stream wrapper and nothing in WordPress. It is understood on read and never written back.',
			),
			'nothing but traversal is refused' => array(
				'..',
				'',
				'An empty result tells the compiler to fall back to its default rather than write a path meaning "the directory itself".',
			),
			'blank stays blank'                => array(
				'',
				'',
				'A blank field means "use the default", which is the compiler\'s decision and not this method\'s.',
			),
		);
	}
}
