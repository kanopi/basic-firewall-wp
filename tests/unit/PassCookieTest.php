<?php
/**
 * Tests for the pass cookie's name and the solved marker.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Challenge\Pass_Cookie;
use Kanopi\BasicFirewall\Runtime\Decision_Dispatcher;
use Kanopi\BasicFirewall\Runtime\Outcome_Responder;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Event\RequestChallenged;
use Kanopi\Firewall\Plugins\PluginInterface;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The pass cookie is named on the Challenge screen, and the marker follows it (#35).
 *
 * @covers \Kanopi\BasicFirewall\Challenge\Pass_Cookie
 * @covers \Kanopi\BasicFirewall\Runtime\Outcome_Responder
 * @covers \Kanopi\BasicFirewall\Runtime\Decision_Dispatcher
 */
final class PassCookieTest extends TestCase {

	/**
	 * A name used in these tests other than the default.
	 */
	private const NAME = 'STYXKEY_bfw_pass';

	/**
	 * The marker a solve under NAME sets.
	 */
	private const MARKER = self::NAME . '_solved';

	/**
	 * The stored name, trimmed; empty or unusable falls back to the default.
	 */
	public function test_the_name(): void {
		$this->assertSame( 'bfw_pass', Pass_Cookie::name( '' ) );
		$this->assertSame( 'bfw_pass', Pass_Cookie::name( '   ' ) );
		$this->assertSame( 'bfw_pass', Pass_Cookie::name( 'bfw_pass' ) );
		$this->assertSame( self::NAME, Pass_Cookie::name( self::NAME ) );
		$this->assertSame( 'my_pass', Pass_Cookie::name( ' my_pass ' ) );
		$this->assertSame( 'bfw_pass', Pass_Cookie::name( 'my pass' ), 'A name with a space was compiled.' );
	}

	/**
	 * Valid cookie names are RFC 6265 tokens.
	 */
	public function test_valid_names(): void {
		foreach ( array( 'bfw_pass', self::NAME, 'wp-bfw', 'a.b', 'x!#$%&\'*+-.^_`|~9' ) as $name ) {
			$this->assertTrue( Pass_Cookie::is_valid( $name ), $name . ' should be valid.' );
		}

		foreach ( array( '', ' ', 'a b', 'a=b', 'a;b', 'a,b', "a\tb", 'a"b', 'a(b)', 'a/b', 'a@b', 'a:b', 'a[b]', 'a?b', 'a{b}', 'caf\u{e9}' ) as $name ) {
			$this->assertFalse( Pass_Cookie::is_valid( $name ), $name . ' should be invalid.' );
		}
	}

	/**
	 * The marker is named after the pass cookie, prefix and all.
	 */
	public function test_the_marker_name_derives_from_the_cookie_name(): void {
		$this->assertSame( 'bfw_pass_solved', Pass_Cookie::marker_name( 'bfw_pass' ) );
		$this->assertSame( self::NAME . '_solved', Pass_Cookie::marker_name( self::NAME ) );
	}

	/**
	 * A solve sets the pass under the given name, and the short-lived marker.
	 */
	public function test_a_solve_sets_the_pass_and_the_marker(): void {
		$cookies = Outcome_Responder::solved_cookies( 'the-token', self::NAME, true );

		$this->assertSame( self::NAME, $cookies[0]['name'] );
		$this->assertSame( 'the-token', $cookies[0]['value'] );
		$this->assertTrue( $cookies[0]['options']['httponly'] );
		$this->assertTrue( $cookies[0]['options']['secure'] );

		$this->assertSame( self::NAME . '_solved', $cookies[1]['name'] );
		$this->assertEqualsWithDelta( time(), (int) $cookies[1]['value'], 2 );
		$this->assertEqualsWithDelta( time() + Outcome_Responder::SOLVED_MARKER_TTL, $cookies[1]['options']['expires'], 2 );
		$this->assertTrue( $cookies[1]['options']['httponly'] );
	}

	/**
	 * The responder's copy of the marker's lifetime is the marker's own.
	 */
	public function test_the_marker_lifetime_is_stated_once(): void {
		$this->assertSame( Pass_Cookie::MARKER_TTL, Outcome_Responder::SOLVED_MARKER_TTL );
	}

	/**
	 * The marker without the pass, fresh, is a pass that went missing; nothing else is.
	 */
	public function test_a_missing_pass_is_recognised(): void {
		$recent = (string) time();

		$this->assertTrue( Pass_Cookie::went_missing( self::NAME, array( self::MARKER => $recent ) ) );

		foreach ( $this->not_missing( $recent ) as $case => $cookies ) {
			$this->assertFalse( Pass_Cookie::went_missing( self::NAME, $cookies ), $case );
		}

		$this->assertFalse( Pass_Cookie::went_missing( '', array( '_solved' => $recent ) ), 'No pass cookie name, no notice.' );
	}

	/**
	 * The dispatcher adds the notice to the library's RequestChallenged event (#46).
	 *
	 * The library dispatches the event before it writes the interstitial and
	 * reads the notices back into the page, in either mode, so this is the
	 * one place the line is added.
	 */
	public function test_the_dispatcher_adds_the_notice_to_the_challenge(): void {
		$recent = (string) time();

		try {
			$event = $this->challenged( array( self::MARKER => $recent ) );
			( new Decision_Dispatcher( self::NAME ) )->dispatch( $event );

			$this->assertSame( array( Pass_Cookie::MISSING_NOTICE ), $event->getNotices() );

			foreach ( $this->not_missing( $recent ) as $case => $cookies ) {
				$event = $this->challenged( $cookies );
				( new Decision_Dispatcher( self::NAME ) )->dispatch( $event );

				$this->assertSame( array(), $event->getNotices(), $case . ': the notice was added.' );
			}

			$event = $this->challenged( array( self::MARKER => $recent ) );
			( new Decision_Dispatcher() )->dispatch( $event );

			$this->assertSame( array(), $event->getNotices(), 'A dispatcher that was not told the cookie name added a notice.' );
		} finally {
			Decision_Dispatcher::reset();
		}
	}

	/**
	 * In exception mode the notice reaches the page through the render context, above the form.
	 */
	public function test_a_missing_pass_is_explained_on_the_interstitial(): void {
		$missing = Outcome_Responder::challenge_response( $this->challenge( array( Pass_Cookie::MISSING_NOTICE ) ), $this->request( array( self::MARKER => (string) time() ) ) );

		$this->assertSame( 503, $missing['status'] );
		$this->assertStringContainsString( 'the verification cookie did not come back', $missing['body'] );
		$this->assertLessThan( strpos( $missing['body'], '<form' ), strpos( $missing['body'], 'the verification cookie did not come back' ), 'The notice is not above the form.' );
		$this->assertNotNull( $missing['warning'], 'A pass that went missing was not logged.' );
		$this->assertSame( 'no-store', $missing['headers']['Surrogate-Control'] ?? null, 'The interstitial is no longer kept out of the cache.' );

		foreach ( $this->not_missing( (string) time() ) as $case => $cookies ) {
			$response = Outcome_Responder::challenge_response( $this->challenge(), $this->request( $cookies ) );

			$this->assertStringNotContainsString( 'the verification cookie did not come back', $response['body'], $case . ': the notice was shown.' );
			$this->assertNull( $response['warning'], $case );
		}
	}

	/**
	 * Cookies that do not mean the pass went missing.
	 *
	 * @param string $recent A marker value from a moment ago.
	 *
	 * @return array<string, array<string, string>>
	 */
	private function not_missing( string $recent ): array {
		return array(
			'never solved'           => array(),
			'pass arrived'           => array(
				self::MARKER => $recent,
				self::NAME   => 'refused-token',
			),
			'marker expired'         => array( self::MARKER => (string) ( time() - Outcome_Responder::SOLVED_MARKER_TTL - 5 ) ),
			'marker from the future' => array( self::MARKER => (string) ( time() + 600 ) ),
			'marker not a time'      => array( self::MARKER => '<script>' ),
			'old fixed marker name'  => array( 'wp-bfw-solved' => $recent ),
		);
	}

	/**
	 * The library's RequestChallenged event for a request carrying the given cookies.
	 *
	 * @param array<string, string> $cookies Cookies.
	 */
	private function challenged( array $cookies ): RequestChallenged {
		return new RequestChallenged( $this->request( $cookies ), $this->createMock( PluginInterface::class ), 'math' );
	}

	/**
	 * A challenge as the firewall throws it in exception mode.
	 *
	 * @param list<string> $notices The render context's notices.
	 */
	private function challenge( array $notices = array() ): ChallengeRequiredException {
		return new ChallengeRequiredException(
			'Challenge required',
			null,
			new MathChallengeProvider( new TokenManager( str_repeat( 'unit-secret-', 3 ) ) ),
			'math',
			array(
				'submit_url'  => '/basic-firewall/challenge',
				'redirect_to' => '/somewhere',
				'ttl'         => '600',
				'cookie_name' => self::NAME,
				'header_name' => 'X-Firewall-Pass',
				'notices'     => $notices,
			)
		);
	}

	/**
	 * A GET carrying the given cookies.
	 *
	 * @param array<string, string> $cookies Cookies.
	 */
	private function request( array $cookies ): Request {
		return Request::create( '/somewhere', 'GET', array(), $cookies );
	}
}
