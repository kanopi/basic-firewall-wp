<?php
/**
 * What the shipped code may not depend on.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use PHPUnit\Framework\TestCase;

/**
 * Constants that are not defined everywhere PHP runs.
 *
 * `GLOB_BRACE` is a GNU extension to glob(). musl libc -- Alpine, and so a
 * good share of container images -- does not have it before PHP 8.5, and an
 * undefined constant is a fatal error. uninstall.php used it to empty
 * directories, so on those hosts uninstall deleted the options and stopped.
 *
 * @coversNothing
 */
final class PortabilityTest extends TestCase {

	/**
	 * No file that ships in the zip names GLOB_BRACE.
	 */
	public function test_nothing_shipped_uses_glob_brace(): void {
		$root  = dirname( __DIR__, 2 );
		$files = array( $root . '/basic-firewall.php', $root . '/bootstrap.php', $root . '/loader.php', $root . '/uninstall.php', $root . '/mu-plugin/basic-firewall-loader.php' );

		$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . '/src', \FilesystemIterator::SKIP_DOTS ) );

		foreach ( $iterator as $file ) {
			if ( 'php' === $file->getExtension() ) {
				$files[] = $file->getPathname();
			}
		}

		$offenders = array();

		foreach ( $files as $file ) {
			$tokens = token_get_all( (string) file_get_contents( $file ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- reading the plugin's own source.

			foreach ( $tokens as $token ) {
				if ( is_array( $token ) && T_STRING === $token[0] && 'GLOB_BRACE' === $token[1] ) {
					$offenders[] = substr( $file, strlen( $root ) + 1 );
				}
			}
		}

		$this->assertSame( array(), array_values( array_unique( $offenders ) ), 'GLOB_BRACE is undefined on musl libc before PHP 8.5, which makes it a fatal error there.' );
	}
}
