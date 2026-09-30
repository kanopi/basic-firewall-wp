<?php
/**
 * Tests for the pass cookie's name, and Pantheon's pass-through patterns.
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

// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- simulating Pantheon's environment is the point, and tearDown() clears it.

/**
 * On Pantheon a name nobody chose becomes one the edge forwards (#35).
 *
 * Pantheon's CDN strips request cookies matching none of its patterns, and
 * `bfw_pass` matches none, so a solved challenge was challenged again forever.
 *
 * @covers \Kanopi\BasicFirewall\Challenge\Pass_Cookie
 * @covers \Kanopi\BasicFirewall\Runtime\Outcome_Responder
 */
final class PassCookieTest extends TestCase {

	/**
	 * Clear the environment variable a test may have set.
	 */
	protected function tearDown(): void {
		putenv( 'PANTHEON_ENVIRONMENT' );
		unset( $_ENV['PANTHEON_ENVIRONMENT'], $_SERVER['PANTHEON_ENVIRONMENT'] );

		parent::tearDown();
	}

	/**
	 * Empty, or the old default, is automatic; anything else is a choice.
	 */
	public function test_the_effective_name(): void {
		$this->assertSame( 'bfw_pass', Pass_Cookie::effective_name( '', false ) );
		$this->assertSame( 'bfw_pass', Pass_Cookie::effective_name( 'bfw_pass', false ) );
		$this->assertSame( 'STYXKEY_bfw_pass', Pass_Cookie::effective_name( '', true ) );
		$this->assertSame( 'STYXKEY_bfw_pass', Pass_Cookie::effective_name( 'bfw_pass', true ) );
		$this->assertSame( 'my_pass', Pass_Cookie::effective_name( 'my_pass', true ), 'A name the admin chose was overridden on Pantheon.' );
		$this->assertSame( 'my_pass', Pass_Cookie::effective_name( ' my_pass ', false ) );

		$this->assertSame( Pass_Cookie::REASON_PANTHEON, Pass_Cookie::reason( '', true ) );
		$this->assertSame( Pass_Cookie::REASON_DEFAULT, Pass_Cookie::reason( '', false ) );
		$this->assertSame( Pass_Cookie::REASON_CHOSEN, Pass_Cookie::reason( 'my_pass', true ) );
	}

	/**
	 * PANTHEON_ENVIRONMENT is read from the environment, $_ENV and $_SERVER.
	 */
	public function test_pantheon_is_detected_from_each_source(): void {
		$this->assertFalse( Pass_Cookie::on_pantheon() );
		$this->assertSame( 'bfw_pass', Pass_Cookie::effective_name( '' ) );

		putenv( 'PANTHEON_ENVIRONMENT=dev' );
		$this->assertTrue( Pass_Cookie::on_pantheon() );
		$this->assertSame( 'STYXKEY_bfw_pass', Pass_Cookie::effective_name( '' ) );
		putenv( 'PANTHEON_ENVIRONMENT' );

		$_ENV['PANTHEON_ENVIRONMENT'] = 'live';
		$this->assertTrue( Pass_Cookie::on_pantheon() );
		unset( $_ENV['PANTHEON_ENVIRONMENT'] );

		$_SERVER['PANTHEON_ENVIRONMENT'] = 'test';
		$this->assertTrue( Pass_Cookie::on_pantheon() );
		$_SERVER['PANTHEON_ENVIRONMENT'] = '';
		$this->assertFalse( Pass_Cookie::on_pantheon(), 'An empty value was taken for Pantheon.' );
	}

	/**
	 * The names Pantheon's edge forwards, and some it strips.
	 */
	public function test_pantheon_pass_through_patterns(): void {
		foreach ( array( 'STYXKEY_bfw_pass', 'STYXKEY-x', 'NO_CACHE', 'SESS0a1b', 'SSESSabc', 'wordpress_logged_in_x', 'wp-bfw-solved', 'comment_author_x', 'woocommerce_cart_hash' ) as $name ) {
			$this->assertTrue( Pass_Cookie::forwarded_by_pantheon( $name ), $name . ' should be forwarded.' );
		}

		foreach ( array( 'bfw_pass', 'fw_challenge_pass', 'STYXKEY', 'styxkey_x', 'STYXKEY_a.b', 'SESSABC', 'my_wp-cookie' ) as $name ) {
			$this->assertFalse( Pass_Cookie::forwarded_by_pantheon( $name ), $name . ' should be stripped.' );
		}

		$this->assertTrue( Pass_Cookie::forwarded_by_pantheon( Pass_Cookie::PANTHEON_NAME ) );
		$this->assertTrue( Pass_Cookie::forwarded_by_pantheon( Outcome_Responder::SOLVED_MARKER ), 'The solved marker would be stripped with the pass.' );
	}

	/**
	 * A solve sets the pass under the given name, and the short-lived marker.
	 */
	public function test_a_solve_sets_the_pass_and_the_marker(): void {
		$cookies = Outcome_Responder::solved_cookies( 'the-token', 'STYXKEY_bfw_pass', true );

		$this->assertSame( 'STYXKEY_bfw_pass', $cookies[0]['name'] );
		$this->assertSame( 'the-token', $cookies[0]['value'] );
		$this->assertTrue( $cookies[0]['options']['httponly'] );
		$this->assertTrue( $cookies[0]['options']['secure'] );

		$this->assertSame( Outcome_Responder::SOLVED_MARKER, $cookies[1]['name'] );
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

		$missing = Outcome_Responder::challenge_response( $challenge, $this->request( array( Outcome_Responder::SOLVED_MARKER => $recent ) ) );

		$this->assertSame( 503, $missing['status'] );
		$this->assertStringContainsString( 'bfw-missing-pass', $missing['body'] );
		$this->assertStringContainsString( 'the verification cookie did not come back', $missing['body'] );
		$this->assertLessThan( strpos( $missing['body'], '<form' ), strpos( $missing['body'], 'bfw-missing-pass' ), 'The notice is not above the form.' );
		$this->assertNotNull( $missing['warning'] );
		$this->assertSame( 'no-store', $missing['headers']['Surrogate-Control'] ?? null, 'The interstitial is no longer kept out of the cache.' );

		$cases = array(
			'never solved'           => array(),
			'pass arrived'           => array(
				Outcome_Responder::SOLVED_MARKER => $recent,
				'STYXKEY_bfw_pass'               => 'refused-token',
			),
			'marker expired'         => array( Outcome_Responder::SOLVED_MARKER => (string) ( time() - Outcome_Responder::SOLVED_MARKER_TTL - 5 ) ),
			'marker from the future' => array( Outcome_Responder::SOLVED_MARKER => (string) ( time() + 600 ) ),
			'marker not a time'      => array( Outcome_Responder::SOLVED_MARKER => '<script>' ),
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
				'cookie_name' => 'STYXKEY_bfw_pass',
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
