<?php
/**
 * A request factory that throws, for EarlyPathExceptionModeTest.
 *
 * @package Kanopi\BasicFirewall
 */

// phpcs:disable Generic.Files.OneObjectStructurePerFile, WordPress.NamingConventions -- a stand-in under the real class's name.

namespace Kanopi\BasicFirewall\Runtime;

/**
 * Required by the wp-config.php fixture before bootstrap.php, under the real
 * factory's name, so the bootstrap finds this class already loaded and builds
 * its request with it -- inside the try around evaluation. What it throws is
 * not a verdict, so it stands in for any failure of the firewall partway
 * through evaluating: the bootstrap must fail open, and say so in the log.
 */
final class Request_Factory {

	/**
	 * Fail to build the request.
	 *
	 * @param string $request_class The Request class.
	 *
	 * @throws \RuntimeException Always.
	 */
	public static function from_globals_of( string $request_class ): object {
		unset( $request_class );

		throw new \RuntimeException( 'the fixture broke evaluation for redis://someone:hunter2@cache.internal:6379' );
	}
}
