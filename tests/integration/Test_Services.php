<?php
/**
 * The services a test needs from the machine running it: Redis, APCu, a network.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

/**
 * Skip where a service is absent -- unless the environment says it is there.
 *
 * A test that skips when Redis does not answer is right on a laptop and wrong
 * in CI: a CI job whose Redis container failed to start, or whose image lost
 * ext-redis, would go green with the Redis tests quietly skipped, which is how
 * they came to have never run at all (#43). So each service can be declared
 * present, and a declared service that is missing fails the test instead:
 *
 * - `BASIC_FIREWALL_TEST_REDIS=host:port` -- a Redis server. Without it the
 *   tests try 127.0.0.1:6379 and skip when nothing answers.
 * - `BASIC_FIREWALL_TEST_APCU=1` -- APCu enabled for the CLI
 *   (`apc.enable_cli=1`).
 * - `BASIC_FIREWALL_MULTISITE=1` -- the site is a multisite network. Tests of a
 *   network fail on a single site then, and single-site assertions skip.
 */
trait Test_Services {

	/**
	 * The Redis server to test against: skip, or fail when one was promised.
	 *
	 * Every key a test writes should carry a random prefix, so a shared server
	 * is safe to use.
	 *
	 * @return array{0: string, 1: int}
	 */
	private function redis_server(): array {
		$spec     = getenv( 'BASIC_FIREWALL_TEST_REDIS' );
		$promised = is_string( $spec ) && '' !== $spec;
		$spec     = $promised ? $spec : '127.0.0.1:6379';

		$parts = explode( ':', $spec, 2 );
		$host  = $parts[0];
		$port  = isset( $parts[1] ) && (int) $parts[1] > 0 ? (int) $parts[1] : 6379;

		if ( ! class_exists( 'Redis' ) ) {
			$this->service_missing( $promised, 'ext-redis is not loaded.' );
		}

		try {
			$probe = new \Redis();

			if ( ! $probe->connect( $host, $port, 0.5 ) || ! $probe->ping() ) {
				$this->service_missing( $promised, sprintf( 'No Redis server answered at %s:%d. Set BASIC_FIREWALL_TEST_REDIS to host:port to run this.', $host, $port ) );
			}

			$probe->close();
		} catch ( \RedisException $e ) {
			$this->service_missing( $promised, sprintf( 'No Redis server answered at %s:%d (%s). Set BASIC_FIREWALL_TEST_REDIS to host:port to run this.', $host, $port, $e->getMessage() ) );
		}

		return array( $host, $port );
	}

	/**
	 * Skip unless APCu is enabled in this SAPI, or fail when it was promised.
	 */
	private function requires_apcu(): void {
		if ( ! function_exists( 'apcu_enabled' ) || ! apcu_enabled() ) {
			$this->service_missing( self::apcu_expected(), 'APCu is not enabled in this SAPI (apc.enable_cli is usually off).' );
		}
	}

	/**
	 * Skip unless this is a multisite network, or fail when one was promised.
	 */
	private function requires_multisite(): void {
		if ( ! is_multisite() ) {
			$this->service_missing( self::multisite_expected(), 'Not a multisite install. Run the suite against a network with BASIC_FIREWALL_MULTISITE=1.' );
		}
	}

	/**
	 * Whether the environment says APCu is enabled.
	 */
	private static function apcu_expected(): bool {
		return '1' === getenv( 'BASIC_FIREWALL_TEST_APCU' );
	}

	/**
	 * Whether the environment says the site is a multisite network.
	 */
	private static function multisite_expected(): bool {
		return '1' === getenv( 'BASIC_FIREWALL_MULTISITE' );
	}

	/**
	 * Skip, or fail when the environment promised the service.
	 *
	 * @param bool   $promised Whether the environment declared it present.
	 * @param string $why      What is missing.
	 */
	private function service_missing( bool $promised, string $why ): never {
		if ( $promised ) {
			$this->fail( $why . ' The environment declares it present, so this is a broken test environment, not a skip.' );
		}

		$this->markTestSkipped( $why );
	}
}
