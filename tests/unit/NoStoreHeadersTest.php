<?php
/**
 * Tests that every response the responder writes stays out of caches.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use Kanopi\BasicFirewall\Runtime\Outcome_Responder;
use Kanopi\Firewall\Challenge\ChallengeProviderInterface;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Utility\NoStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

/**
 * The full no-store set, on every response, and a challenge never fails open.
 *
 * #34: a challenged page reached Pantheon's edge with WordPress's
 * `Cache-Control: max-age=3600` and was served from there to everybody. The
 * responder's answers carried `no-store` and `Pragma` only, which is not
 * enough for an edge that caches a `no-store` response (kanopi/firewall#417),
 * so each one now carries the library's whole set from kanopi/firewall#418.
 *
 * Sending a response ends the request, so what is pinned here is what each
 * response is composed of.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Outcome_Responder
 */
final class NoStoreHeadersTest extends TestCase {

	/**
	 * The set, as kanopi/firewall#418 defines it.
	 */
	private const EXPECTED = array(
		'Cache-Control'     => 'private, no-store, no-cache, must-revalidate, max-age=0',
		'Pragma'            => 'no-cache',
		'Expires'           => '0',
		'Surrogate-Control' => 'no-store',
		'CDN-Cache-Control' => 'no-store',
	);

	/**
	 * The responder's set is the library's, and the library's is #418's.
	 */
	public function test_the_set_is_the_librarys(): void {
		$this->assertSame( self::EXPECTED, NoStore::HEADERS );
		$this->assertSame( NoStore::HEADERS, Outcome_Responder::no_store_headers() );
	}

	/**
	 * The bootstrap's copy, used when nothing else can answer, is the same set.
	 */
	public function test_the_bootstraps_set_is_the_same(): void {
		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

		$this->assertSame( self::EXPECTED, basic_firewall_no_store_headers() );
	}

	/**
	 * Every kind of response carries every header of the set.
	 *
	 * @dataProvider responses
	 *
	 * @param callable $compose Composes the response.
	 * @param int      $status  The status it should have.
	 */
	public function test_every_response_carries_the_whole_set( callable $compose, int $status ): void {
		$response = $compose();

		$this->assertSame( $status, $response['status'] );

		foreach ( self::EXPECTED as $name => $value ) {
			$this->assertSame( $value, $response['headers'][ $name ] ?? null, sprintf( '%s is missing or wrong.', $name ) );
		}
	}

	/**
	 * One of each response the responder writes.
	 *
	 * @return array<string, array{0: callable, 1: int}>
	 */
	public function responses(): array {
		$json = Request::create( '/basic-firewall/challenge', 'POST', array(), array(), array(), array( 'HTTP_ACCEPT' => 'application/json' ) );

		return array(
			'challenge'              => array( fn() => Outcome_Responder::challenge_response( self::challenge(), Request::create( '/learning-resources/' ) ), 503 ),
			'unrenderable challenge' => array( fn() => Outcome_Responder::challenge_response( new ChallengeRequiredException( 'no provider' ), Request::create( '/learning-resources/' ) ), 503 ),
			'block'                  => array( fn() => Outcome_Responder::blocked_response( new FirewallBlockedException( 'Blocked.', 403 ) ), 403 ),
			'lockdown'               => array( fn() => Outcome_Responder::blocked_response( new FirewallLockdownException( 'Closed.' ) ), 503 ),
			'redirect'               => array( fn() => Outcome_Responder::redirect_response( new FirewallRedirectException( '/notice', 307 ) ), 307 ),
			'solved, as JSON'        => array( fn() => Outcome_Responder::solved_http_response( new ChallengeSolvedException( 'token', '/where' ), $json ), 200 ),
			'solved, as a redirect'  => array( fn() => Outcome_Responder::solved_http_response( new ChallengeSolvedException( 'token', '/where' ), Request::create( '/basic-firewall/challenge', 'POST' ) ), 302 ),
			'refusal'                => array( fn() => Outcome_Responder::refusal_response(), 503 ),
		);
	}

	/**
	 * A challenge is the provider's interstitial, 503 with Retry-After.
	 */
	public function test_a_challenge_is_the_interstitial(): void {
		$response = Outcome_Responder::challenge_response( self::challenge(), Request::create( '/learning-resources/' ) );

		$this->assertSame( '<form id="challenge-form">stub</form>', $response['body'] );
		$this->assertSame( '60', $response['headers']['Retry-After'] );
		$this->assertNull( $response['warning'] );
	}

	/**
	 * A challenge that cannot be rendered is refused, never let through.
	 *
	 * The reason is carried out for the log, which is where the next report
	 * will find it rather than finding nothing.
	 */
	public function test_a_challenge_that_cannot_be_rendered_is_a_refusal(): void {
		foreach ( array(
			'no provider' => array( new ChallengeRequiredException( 'no provider' ), Request::create( '/learning-resources/' ) ),
			'no request'  => array( self::challenge(), null ),
			'throws'      => array( self::challenge( true ), Request::create( '/learning-resources/' ) ),
		) as $case => $arguments ) {
			$response = Outcome_Responder::challenge_response( ...$arguments );

			$this->assertSame( 503, $response['status'], $case );
			$this->assertStringContainsString( 'Verification required', $response['body'], $case );
			$this->assertIsString( $response['warning'], $case . ': nothing says why the challenge was not shown.' );
		}
	}

	/**
	 * A verdict is known in either class spelling; anything else is not one.
	 */
	public function test_a_verdict_is_known_in_either_spelling(): void {
		require_once dirname( __DIR__ ) . '/integration/fixtures/foreign-verdict.php';

		$this->assertSame( 'challenge', Outcome_Responder::verdict_kind( new ChallengeRequiredException( 'x' ) ) );
		$this->assertSame( 'challenge', Outcome_Responder::verdict_kind( new \Kanopi\BasicFirewall\Vendor\Kanopi\Firewall\Exception\ChallengeRequiredException( 'x' ) ) );
		$this->assertSame( 'blocked', Outcome_Responder::verdict_kind( new FirewallLockdownException( 'x' ) ) );
		$this->assertSame( 'redirect', Outcome_Responder::verdict_kind( new FirewallRedirectException( '/x' ) ) );
		$this->assertSame( 'solved', Outcome_Responder::verdict_kind( new ChallengeSolvedException( 't', '/' ) ) );
		$this->assertNull( Outcome_Responder::verdict_kind( new \RuntimeException( 'x' ) ) );
	}

	/**
	 * A challenge with a stub provider.
	 *
	 * @param bool $throws Whether rendering throws.
	 */
	private static function challenge( bool $throws = false ): ChallengeRequiredException {
		$provider = new class( $throws ) implements ChallengeProviderInterface {

			/**
			 * Whether rendering throws.
			 *
			 * @var bool
			 */
			private bool $throws;

			/**
			 * Build the stub.
			 *
			 * @param bool $throws Whether rendering throws.
			 */
			public function __construct( bool $throws ) {
				$this->throws = $throws;
			}

			/**
			 * The provider's name.
			 */
			public function getName(): string {
				return 'stub';
			}

			/**
			 * Render the page, or fail to.
			 *
			 * @param Request              $request The request.
			 * @param array<string, mixed> $context The render context.
			 *
			 * @throws \RuntimeException When built to.
			 */
			public function renderInterstitial( Request $request, array $context ): string {
				if ( $this->throws ) {
					throw new \RuntimeException( 'the widget could not be built' );
				}

				return '<form id="challenge-form">stub</form>';
			}

			/**
			 * Never solved.
			 *
			 * @param Request $request The request.
			 */
			public function verifySolution( Request $request ): bool {
				return false;
			}
		};

		return new ChallengeRequiredException( 'Challenge required by plugin: stub', null, $provider, 'stub', array() );
	}
}
