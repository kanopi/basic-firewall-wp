<?php
/**
 * Tests for the pass cookie's name and the solved marker.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Challenge\Pass_Cookie;
use Kanopi\BasicFirewall\Runtime\Outcome_Responder;
use Kanopi\Firewall\Challenge\MathChallengeProvider;
use Kanopi\Firewall\Challenge\TokenManager;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The pass cookie is named on the Challenge screen, and the marker follows it (#35).
 *
 * @covers \Kanopi\BasicFirewall\Challenge\Pass_Cookie
 * @covers \Kanopi\BasicFirewall\Runtime\Outcome_Responder
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
	 * A re-challenge carrying the marker and no pass says why.
	 */
	public function test_a_missing_pass_is_explained_on_the_interstitial(): void {
		$challenge = $this->challenge();
		$recent    = (string) time();

		$missing = Outcome_Responder::challenge_response( $challenge, $this->request( array( self::MARKER => $recent ) ) );

		$this->assertSame( 503, $missing['status'] );
		$this->assertStringContainsString( 'bfw-missing-pass', $missing['body'] );
		$this->assertStringContainsString( 'the verification cookie did not come back', $missing['body'] );
		$this->assertLessThan( strpos( $missing['body'], '<form' ), strpos( $missing['body'], 'bfw-missing-pass' ), 'The notice is not above the form.' );
		$this->assertNotNull( $missing['warning'] );
		$this->assertSame( 'no-store', $missing['headers']['Surrogate-Control'] ?? null, 'The interstitial is no longer kept out of the cache.' );

		$cases = array(
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

		foreach ( $cases as $case => $cookies ) {
			$response = Outcome_Responder::challenge_response( $challenge, $this->request( $cookies ) );

			$this->assertStringNotContainsString( 'bfw-missing-pass', $response['body'], $case . ': the notice was shown.' );
			$this->assertNull( $response['warning'], $case );
		}
	}

	/**
	 * A challenge as the firewall throws it in exception mode.
	 */
	private function challenge(): ChallengeRequiredException {
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
