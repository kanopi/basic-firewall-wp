<?php
/**
 * Tests for how an `exception` mode redirect is answered.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Runtime\Outcome_Responder;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use PHPUnit\Framework\TestCase;

/**
 * A redirect outcome is answered with a redirect, not a refusal.
 *
 * `response: redirect` arrived in kanopi/firewall 2.26.0. In `exception` mode
 * the library throws it for the host to answer, and the responder used to have
 * no branch for it: it fell through to "anything else is a failure of the
 * firewall", so the visitor was served the page the rule was written to send
 * them away from, and a firewall error was logged on every request it matched.
 *
 * Sending the response ends the request, so what is pinned here is the
 * decision -- where to, and with which status.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Outcome_Responder
 */
final class OutcomeResponderTest extends TestCase {

	/**
	 * The destination and status the rule chose are the ones sent.
	 */
	public function test_a_redirect_keeps_its_destination_and_status(): void {
		$target = Outcome_Responder::redirect_target( new FirewallRedirectException( 'https://example.com/elsewhere', 301 ) );

		$this->assertSame( 'https://example.com/elsewhere', $target['location'] );
		$this->assertSame( 301, $target['status'] );
	}

	/**
	 * A redirect with no status of its own is a temporary one.
	 */
	public function test_a_redirect_defaults_to_temporary(): void {
		$target = Outcome_Responder::redirect_target( new FirewallRedirectException( '/elsewhere' ) );

		$this->assertSame( '/elsewhere', $target['location'] );
		$this->assertSame( 302, $target['status'] );
	}

	/**
	 * The four redirect statuses the library honours pass through untouched.
	 */
	public function test_every_status_the_library_honours_is_kept(): void {
		foreach ( array( 301, 302, 307, 308 ) as $status ) {
			$this->assertSame(
				$status,
				Outcome_Responder::redirect_target( new FirewallRedirectException( '/elsewhere', $status ) )['status']
			);
		}
	}

	/**
	 * A status that would not redirect is answered with 302.
	 *
	 * A 200 carrying a Location header is a page, and a 403 one a refusal;
	 * neither sends the visitor anywhere, which is the one thing the rule asked
	 * for.
	 */
	public function test_a_status_that_would_not_redirect_becomes_temporary(): void {
		foreach ( array( 200, 403, 0, 399 ) as $status ) {
			$this->assertSame(
				302,
				Outcome_Responder::redirect_target( new FirewallRedirectException( '/elsewhere', $status ) )['status'],
				sprintf( 'Status %d was sent as-is.', $status )
			);
		}
	}
}
