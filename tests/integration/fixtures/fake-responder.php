<?php
/**
 * A responder that fails, for EarlyPathExceptionModeTest.
 *
 * @package Kanopi\BasicFirewall
 */

// phpcs:disable Generic.Files.OneObjectStructurePerFile, WordPress.NamingConventions -- a stand-in under the real class's name.

namespace Kanopi\BasicFirewall\Runtime;

/**
 * Required by the wp-config.php fixture before bootstrap.php, under the real
 * responder's name, so the bootstrap finds this class already loaded and
 * answers with it. It fails in the way the request header names: `throws`,
 * or `returns`, which lets the request continue the way the real one does
 * for a verdict it takes for a firewall failure.
 */
final class Outcome_Responder {

	/**
	 * Fail to answer.
	 *
	 * @param \Throwable $outcome What the firewall threw.
	 * @param mixed      $request The request.
	 *
	 * @throws \RuntimeException When asked to.
	 */
	public function respond( \Throwable $outcome, $request = null ): bool {
		unset( $outcome, $request );

		if ( 'throws' === ( $_SERVER['HTTP_X_BFW_TEST_RESPONDER'] ?? '' ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared against a literal, in a test fixture.
			throw new \RuntimeException( 'the responder broke' );
		}

		return true;
	}
}
