<?php
/**
 * `exception` mode on the wp-config.php evaluation path.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Runner;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Symfony\Component\HttpFoundation\Request;

/**
 * A verdict reached before WordPress loads is answered, not waved through.
 *
 * In `exception` mode the library throws each verdict for the host to answer.
 * On the wp-config.php path the bootstrap used to catch all of them and let the
 * request continue -- and the mu-plugin never looked again, because the request
 * was already marked as evaluated. So on the path recommended for every site
 * with a page cache, `exception` mode refused nobody.
 *
 * These drive the real bootstrap under PHP's built-in web server, from a
 * fixture standing in for wp-config.php, because what is under test is what a
 * visitor receives. Called in-process, the responder's exit() would end the
 * test run; and under the CLI the library bypasses itself in every mode but
 * `exception`, so the `block` mode control would be asserting the bypass.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Outcome_Responder
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class EarlyPathExceptionModeTest extends Settings_Snapshot {

	/**
	 * What the fixture prints once the firewall has let a request through.
	 */
	private const SERVED = 'SERVED BY WORDPRESS';

	/**
	 * The banning message the fixtures configure.
	 */
	private const BANNED = 'Refused on the early path.';

	/**
	 * The built-in server's process.
	 *
	 * @var resource|null
	 */
	private static $server = null;

	/**
	 * The built-in server's base URL.
	 *
	 * @var string
	 */
	private static string $base = '';

	/**
	 * The bootstrap's globals as the test process had them.
	 *
	 * @var array{early: mixed, outcome: mixed}
	 */
	private array $globals;

	/**
	 * Start a web server whose every request runs the wp-config.php fixture.
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

		// A free port, found by asking the kernel for one.
		$probe = stream_socket_server( 'tcp://127.0.0.1:0' );

		if ( false === $probe ) {
			return;
		}

		$name = (string) stream_socket_get_name( $probe, false );
		fclose( $probe ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a socket, not a file.

		$port    = (int) substr( $name, (int) strrpos( $name, ':' ) + 1 );
		$fixture = __DIR__ . '/fixtures/wp-config-early-path.php';

		$env = getenv();
		$env = array_merge(
			is_array( $env ) ? $env : array(),
			array(
				'BFW_EARLY_PLUGIN_PATH'  => dirname( __DIR__, 2 ),
				'BFW_EARLY_PRIVATE_PATH' => Plugin::instance()->paths()->base(),
			)
		);

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- a test starting a web server, never loaded by a site.
		$process = proc_open(
			array( PHP_BINARY, '-S', '127.0.0.1:' . $port, $fixture ),
			array(
				0 => array( 'file', '/dev/null', 'r' ),
				1 => array( 'file', '/dev/null', 'w' ),
				2 => array( 'file', '/dev/null', 'w' ),
			),
			$pipes,
			dirname( $fixture ),
			$env
		);

		if ( ! is_resource( $process ) ) {
			return;
		}

		self::$server = $process;
		self::$base   = 'http://127.0.0.1:' . $port;

		// Up to five seconds for it to start listening.
		for ( $i = 0; $i < 50; $i++ ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen -- a socket, refused until the server is up, which is the expected answer.
			$socket = @fsockopen( '127.0.0.1', $port, $errno, $errstr, 0.1 );

			if ( false !== $socket ) {
				fclose( $socket ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a socket, not a file.

				return;
			}

			usleep( 100000 );
		}
	}

	/**
	 * Stop the server.
	 */
	public static function tearDownAfterClass(): void {
		if ( is_resource( self::$server ) ) {
			proc_terminate( self::$server );
			proc_close( self::$server );
		}

		self::$server = null;

		parent::tearDownAfterClass();
	}

	/**
	 * Remember the bootstrap's globals, which some tests replace.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->globals = array(
			'early'   => $GLOBALS['basic_firewall_early'] ?? null,
			'outcome' => $GLOBALS['basic_firewall_outcome'] ?? null,
		);
	}

	/**
	 * Put them back, and release anything a fixture recorded.
	 */
	protected function tearDown(): void {
		$GLOBALS['basic_firewall_early'] = $this->globals['early'];

		if ( null === $this->globals['outcome'] ) {
			unset( $GLOBALS['basic_firewall_outcome'] );
		} else {
			$GLOBALS['basic_firewall_outcome'] = $this->globals['outcome'];
		}

		parent::tearDown();
	}

	/**
	 * A block rule refuses the request, with the plugin's own page.
	 */
	public function test_a_block_rule_refuses_the_request(): void {
		$this->given_rule( 'block', 'exception' );

		$this->assertStringContainsString( self::SERVED, $this->request( '/bfw-early-other' )['body'], 'An unmatched request was refused.' );

		$response = $this->request( '/bfw-early-match' );

		$this->assertSame( 403, $response['status'], 'A matching request was not refused on the early path.' );
		$this->assertStringNotContainsString( self::SERVED, $response['body'], 'The refused request went on to WordPress.' );
		$this->assertStringContainsString( self::BANNED, $response['body'] );

		// The responder's page, not the library's plain-text one: exception
		// mode answered by the plugin, as it is on the normal path.
		$this->assertStringContainsString( 'text/html', $response['type'] );
		$this->assertStringContainsString( 'no-store', $response['cache'] );
	}

	/**
	 * A redirect rule sends the visitor where it says.
	 */
	public function test_a_redirect_rule_redirects_the_request(): void {
		$this->given_rule( 'redirect', 'exception' );

		$response = $this->request( '/bfw-early-match' );

		$this->assertSame( 307, $response['status'], 'A matching request was not redirected on the early path.' );
		$this->assertSame( '/bfw-early-notice', $response['location'] );
		$this->assertStringNotContainsString( self::SERVED, $response['body'] );
		$this->assertStringContainsString( 'no-store', $response['cache'] );
	}

	/**
	 * A challenge rule serves the interstitial, and a working one.
	 *
	 * The page has to be the library's rendered interstitial, not merely a
	 * refusal: it carries the signed provider token, without which a solved
	 * challenge mints a pass the rule refuses.
	 */
	public function test_a_challenge_rule_challenges_the_request(): void {
		$this->given_rule( 'challenge', 'exception' );

		$response = $this->request( '/bfw-early-match' );

		$this->assertSame( 503, $response['status'], 'A matching request was not challenged on the early path.' );
		$this->assertStringNotContainsString( self::SERVED, $response['body'] );
		$this->assertStringContainsString( 'Verification required', $response['body'], 'The interstitial was not rendered.' );
		$this->assertStringContainsString( 'challenge-form', $response['body'], 'The page has no form to answer the challenge with.' );
		$this->assertStringContainsString( 'name="challenge_provider"', $response['body'], 'The signed provider token is missing, so a solution could never be accepted.' );
		$this->assertNotSame( '', $response['retry'] );
	}

	/**
	 * A lockdown refusal keeps its Retry-After.
	 */
	public function test_a_lockdown_is_refused_with_retry_after(): void {
		$this->given_rule( 'block', 'exception', array( 'lockdown' => true ) );

		$response = $this->request( '/bfw-early-other' );

		$this->assertSame( 503, $response['status'], 'Lockdown did not refuse a client off its allowlist.' );
		$this->assertStringNotContainsString( self::SERVED, $response['body'] );
		$this->assertSame( '300', $response['retry'], 'A temporary refusal lost the header that says it is temporary.' );
	}

	/**
	 * `block` mode is answered by the library, exactly as before.
	 */
	public function test_block_mode_is_unchanged(): void {
		$this->given_rule( 'block', 'block' );

		$this->assertStringContainsString( self::SERVED, $this->request( '/bfw-early-other' )['body'], 'An unmatched request was refused.' );

		$response = $this->request( '/bfw-early-match' );

		$this->assertSame( 403, $response['status'] );
		$this->assertStringNotContainsString( self::SERVED, $response['body'] );
		$this->assertStringContainsString( self::BANNED, $response['body'] );

		// The library's own plain-text answer: nothing of this plugin's
		// responder is involved when the library can answer by itself.
		$this->assertStringContainsString( 'text/plain', $response['type'] );
	}

	/**
	 * A request nothing matched goes on to WordPress with nothing left behind.
	 */
	public function test_an_allowed_request_leaves_nothing_for_the_runner(): void {
		$this->given_rule( 'block', 'exception' );

		$response = $this->request( '/bfw-early-other' );

		$this->assertSame( 200, $response['status'] );
		$this->assertStringContainsString( self::SERVED, $response['body'] );
		$this->assertSame( 'no', $response['stashed'] );
		$this->assertSame( 'none', $response['outcome'] );
	}

	/**
	 * "Enable the firewall" unticked stops this path too.
	 *
	 * The setting lives in an option, which this path cannot read, and it was
	 * never compiled -- so a firewall switched off in the admin went on
	 * refusing requests here while every screen said it was off.
	 */
	public function test_enable_unticked_stops_the_early_path(): void {
		$this->given_rule( 'block', 'block', array(), array( 'enabled' => false ) );

		$response = $this->request( '/bfw-early-match' );

		$this->assertSame( 200, $response['status'], 'A firewall switched off in the admin refused a request on the early path.' );
		$this->assertStringContainsString( self::SERVED, $response['body'] );
		$this->assertSame( 'switched-off', $response['reason'] );
		$this->assertSame( 'no', $response['evaluated'], 'The early path claimed a request it did not evaluate, so the runner would not look at it either.' );

		// And switched back on, it refuses again: the sidecar goes with the setting.
		$this->given_rule( 'block', 'block' );

		$this->assertSame( 403, $this->request( '/bfw-early-match' )['status'] );
	}

	/**
	 * On a multisite network this path steps aside for the mu-plugin.
	 *
	 * It runs before WordPress knows which site a request is for, and found
	 * whichever site's private directory the glob reached first -- so every
	 * site was evaluated against one site's rules, and marking the request
	 * evaluated stopped the mu-plugin applying the right ones.
	 */
	public function test_a_network_is_left_to_the_mu_plugin(): void {
		$this->given_rule( 'block', 'block' );

		$this->assertSame( 403, $this->request( '/bfw-early-match' )['status'], 'The fixture does not refuse on a single site, so this test proves nothing.' );

		$response = $this->request( '/bfw-early-match', array( 'X-Bfw-Test-Network' => '1' ) );

		$this->assertSame( 200, $response['status'], 'The early path evaluated a request on a multisite network.' );
		$this->assertSame( 'multisite', $response['reason'] );
		$this->assertSame( 'no', $response['evaluated'], 'The request was marked evaluated, so the mu-plugin would not apply the site\'s own rules.' );

		// And the option says so for a network that defines neither constant
		// where the bootstrap can see it.
		$this->assertTrue( basic_firewall_is_multisite( basic_firewall_options( array( 'multisite' => true ) ) ) );
	}

	/**
	 * Only verdicts are verdicts.
	 *
	 * Anything else the library throws is a failure of the firewall, which the
	 * early path fails open on, as it always has.
	 */
	public function test_the_bootstrap_knows_a_verdict_from_a_failure(): void {
		$this->assertSame( 'solved', basic_firewall_outcome_kind( new ChallengeSolvedException( 'token', '/' ) ) );
		$this->assertSame( 'challenge', basic_firewall_outcome_kind( new ChallengeRequiredException( 'challenge' ) ) );
		$this->assertSame( 'redirect', basic_firewall_outcome_kind( new FirewallRedirectException( '/elsewhere' ) ) );
		$this->assertSame( 'blocked', basic_firewall_outcome_kind( new FirewallBlockedException( 'no' ) ) );
		$this->assertSame( 'blocked', basic_firewall_outcome_kind( new FirewallLockdownException( 'closed' ) ) );
		$this->assertNull( basic_firewall_outcome_kind( new ConfigurationException( 'broken' ) ) );
		$this->assertNull( basic_firewall_outcome_kind( new \RuntimeException( 'broken' ) ) );
	}

	/**
	 * A solved challenge is left for the runner, which picks it up.
	 *
	 * Setting the pass cookie needs the cookie name from settings, so the
	 * bootstrap leaves this one verdict for WordPress. Answering it ends the
	 * request, so what is pinned here is the hand-over.
	 */
	public function test_a_solved_challenge_is_left_for_the_runner(): void {
		$request = Request::create( '/bfw-challenge', 'POST' );
		$solved  = new ChallengeSolvedException( 'a-pass-token', '/where-i-was' );

		$this->assertFalse(
			basic_firewall_answer_outcome( $solved, $request, basic_firewall_options( array( 'plugin_path' => dirname( __DIR__, 2 ) ) ) ),
			'A solved challenge was reported as nothing to answer.'
		);

		$early = Runner::early_outcome();

		$this->assertNotNull( $early, 'The runner cannot see what the bootstrap left for it.' );
		$this->assertSame( $solved, $early['outcome'] );
		$this->assertSame( $request, $early['request'] );
		$this->assertSame( 'solved', $GLOBALS['basic_firewall_early']['outcome'] ?? null );
	}

	/**
	 * A bootstrap that cannot answer refusals itself is reported as critical.
	 */
	public function test_site_health_reports_refusals_the_early_path_cannot_answer(): void {
		$this->given_settings( array( 'global' => array( 'mode' => 'exception' ) ) );

		$GLOBALS['basic_firewall_early'] = array(
			'called'      => true,
			'credentials' => true,
			'evaluated'   => true,
			'reason'      => null,
			'responder'   => false,
		);

		if ( defined( 'BASIC_FIREWALL_MODE' ) && 'exception' !== BASIC_FIREWALL_MODE ) {
			$this->markTestSkipped( 'BASIC_FIREWALL_MODE pins this site to another mode.' );
		}

		$this->assertSame( 'critical', Site_Health::check( 'evaluation' )['status'] );

		// And only in exception mode: in block mode the library answers.
		$this->given_settings( array( 'global' => array( 'mode' => 'block' ) ) );

		$this->assertNotSame(
			'Exception mode cannot answer refusals before a page cache on the wp-config.php path',
			Site_Health::check( 'evaluation' )['label']
		);
	}

	/**
	 * Install one URL rule matching /bfw-early-match, and compile it.
	 *
	 * @param string               $response Rule response.
	 * @param string               $mode     Operating mode.
	 * @param array<string, mixed> $extra    Further global settings.
	 * @param array<string, mixed> $document Further top-level settings.
	 */
	private function given_rule( string $response, string $mode, array $extra = array(), array $document = array() ): void {
		if ( null === self::$server ) {
			$this->markTestSkipped( 'PHP\'s built-in web server could not be started.' );
		}

		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$this->markTestSkipped( 'BASIC_FIREWALL_MODE pins this site\'s mode, so a fixture cannot choose one.' );
		}

		$this->given_settings(
			$document + array(
				'global'    => array_merge(
					array(
						'mode'            => $mode,
						'banning_message' => self::BANNED,

						// Documentation space, which the fixture's own
						// requests never come from.
						'lockdown_allow'  => array( '192.0.2.10' ),
					),
					$extra
				),

				// A signing secret, because a fixture that replaces the whole
				// document wipes the one activation would have generated, and
				// the compiler then refuses to emit a challenge section.
				'challenge' => array(
					'provider' => 'math',
					'secret'   => str_repeat( 'early-path-secret-', 3 ),
				),

				// File storage, which needs no connection: the fixture
				// defines no DB_ constants.
				'storage'   => array(
					'backend' => 'file',
					'file'    => array(
						'storage_file' => 'early-path-test-blocked.data',
						'offense_file' => 'early-path-test-offenses.data',
					),
				),
				'rules'     => array(
					array(
						'id'              => 'early_path_' . $response,
						'type'            => 'url',
						'label'           => 'Early path ' . $response,
						'enabled'         => true,
						'response'        => $response,
						'weight'          => 0,
						'status_code'     => 403,
						'expiration'      => 600,

						// Nobody is written to the block list, so one test's
						// refusal is not the next test's answer.
						'record'          => 'no',
						'redirect_to'     => '/bfw-early-notice',
						'redirect_status' => 307,
						'mark_as'         => '',
						'mark_header'     => '',
						'settings'        => array(
							'match_type' => 'any',
							'conditions' => array(
								array(
									'variable' => 'path',
									'operator' => 'equals',
									'value'    => '/bfw-early-match',
								),
							),
						),
					),
				),
			)
		);

		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile.' );
		$this->assertSame( array(), $result['problems'], 'The fixture compiled with problems.' );
	}

	/**
	 * Make a request of the fixture.
	 *
	 * @param string                $path    Path to request.
	 * @param array<string, string> $headers Request headers.
	 *
	 * @return array{status: int, body: string, type: string, cache: string, location: string, retry: string, stashed: string, outcome: string, reason: string, evaluated: string}
	 */
	private function request( string $path, array $headers = array() ): array {
		$response = wp_remote_get(
			self::$base . $path,
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fail( 'The request failed: ' . $response->get_error_message() );
		}

		return array(
			'status'    => (int) wp_remote_retrieve_response_code( $response ),
			'body'      => (string) wp_remote_retrieve_body( $response ),
			'type'      => (string) wp_remote_retrieve_header( $response, 'content-type' ),
			'cache'     => (string) wp_remote_retrieve_header( $response, 'cache-control' ),
			'location'  => (string) wp_remote_retrieve_header( $response, 'location' ),
			'retry'     => (string) wp_remote_retrieve_header( $response, 'retry-after' ),
			'stashed'   => (string) wp_remote_retrieve_header( $response, 'x-early-stashed' ),
			'outcome'   => (string) wp_remote_retrieve_header( $response, 'x-early-outcome' ),
			'reason'    => (string) wp_remote_retrieve_header( $response, 'x-early-reason' ),
			'evaluated' => (string) wp_remote_retrieve_header( $response, 'x-early-evaluated' ),
		);
	}
}
