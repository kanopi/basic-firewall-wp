<?php
/**
 * The runner refusing a verdict the early path recorded and did not answer.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Runtime\Diagnostics;
use Kanopi\BasicFirewall\Runtime\Runner;

/**
 * The tripwire for an early path that failed open on a verdict (#36).
 *
 * The bootstrap answers every refusal itself. A request that reaches
 * WordPress with a challenge, redirect or block in the bootstrap's report and
 * nothing in the stash was let through by an early path that should have
 * refused it -- an older bootstrap.php, or a regression of #34. The runner
 * refuses it, late, logs why, and leaves the failure for Site Health.
 *
 * It ends the request with exit(), so it cannot be called from here. Real
 * WordPress is served instead, by PHP's built-in web server, behind a
 * router standing in for that early path (fixtures/runner-unanswered-verdict.php);
 * what the visitor receives is asserted over HTTP, and the report the runner
 * saved is read back from the database this process shares.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 * @covers \Kanopi\BasicFirewall\Runtime\Diagnostics
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class RunnerRefusalTest extends Settings_Snapshot {

	/**
	 * What the fixture prints once WordPress has let a request through.
	 */
	private const SERVED = 'SERVED BY WORDPRESS';

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
	 * The PHP error log the fixture writes to.
	 *
	 * @var string
	 */
	private static string $log = '';

	/**
	 * State this test replaces, put back afterwards.
	 *
	 * @var array<string, mixed>
	 */
	private array $saved = array();

	/**
	 * Serve real WordPress behind the fixture.
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		$probe = stream_socket_server( 'tcp://127.0.0.1:0' );

		if ( false === $probe ) {
			return;
		}

		$name = (string) stream_socket_get_name( $probe, false );
		fclose( $probe ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- a socket, not a file.

		$port    = (int) substr( $name, (int) strrpos( $name, ':' ) + 1 );
		$fixture = __DIR__ . '/fixtures/runner-unanswered-verdict.php';
		$home    = wp_parse_url( home_url( '/' ) );

		self::$log = (string) tempnam( sys_get_temp_dir(), 'bfw-runner-log' );

		$env = getenv();
		$env = array_merge(
			is_array( $env ) ? $env : array(),
			array(
				'BFW_RUNNER_WP_LOAD'   => ABSPATH . 'wp-load.php',
				'BFW_RUNNER_HOST'      => (string) ( $home['host'] ?? '' ) . ( isset( $home['port'] ) ? ':' . $home['port'] : '' ),
				'BFW_RUNNER_PATH'      => (string) ( $home['path'] ?? '' ),
				'BFW_RUNNER_ERROR_LOG' => self::$log,
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
			ABSPATH,
			$env
		);

		if ( ! is_resource( $process ) ) {
			return;
		}

		self::$server = $process;
		self::$base   = 'http://127.0.0.1:' . $port;

		for ( $i = 0; $i < 50; $i++ ) {
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_fsockopen -- refused until the server is up, which is the expected answer.
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

		if ( '' !== self::$log ) {
			wp_delete_file( self::$log );
		}

		parent::tearDownAfterClass();
	}

	/**
	 * Save the saved reports, and let the next request write one.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! is_resource( self::$server ) ) {
			$this->markTestSkipped( 'PHP\'s built-in web server could not be started.' );
		}

		$this->saved = array(
			'early'   => $GLOBALS['basic_firewall_early'] ?? null,
			'last'    => get_transient( Diagnostics::LAST ),
			'anomaly' => get_transient( Diagnostics::ANOMALY ),
		);

		// The mode the refusal is judged in, as a site in Block mode.
		$this->given_settings( array( 'global' => array( 'mode' => 'block' ) ) );

		delete_transient( Diagnostics::LAST );
		delete_transient( Diagnostics::ANOMALY );
		Diagnostics::reset_throttle();
		Runner::reset();
	}

	/**
	 * Put the reports back.
	 */
	protected function tearDown(): void {
		$GLOBALS['basic_firewall_early'] = $this->saved['early'] ?? null;

		foreach ( array(
			Diagnostics::LAST    => 'last',
			Diagnostics::ANOMALY => 'anomaly',
		) as $transient => $key ) {
			if ( ! isset( $this->saved[ $key ] ) || false === $this->saved[ $key ] ) {
				delete_transient( $transient );
			} else {
				set_transient( $transient, $this->saved[ $key ], Diagnostics::TTL );
			}
		}

		Diagnostics::reset_throttle();
		Runner::reset();

		parent::tearDown();
	}

	/**
	 * With no verdict recorded, WordPress serves the request.
	 *
	 * The control: without it, a fixture that never reached WordPress at all
	 * would pass every refusal below.
	 */
	public function test_a_request_with_no_verdict_is_served(): void {
		$response = $this->request();

		$this->assertSame( 200, $response['status'], 'The fixture did not reach WordPress, so the refusals below prove nothing.' );
		$this->assertStringContainsString( self::SERVED, $response['body'] );
	}

	/**
	 * A recorded verdict nobody answered is refused, logged and reported.
	 *
	 * @dataProvider verdicts
	 *
	 * @param string $kind The verdict the early path recorded.
	 */
	public function test_an_unanswered_early_verdict_is_refused( string $kind ): void {
		$offset   = $this->log_size();
		$response = $this->request( $kind );

		$this->assertSame( 503, $response['status'], sprintf( 'A %s verdict the early path let through was not refused by the runner.', $kind ) );
		$this->assertStringNotContainsString( self::SERVED, $response['body'], 'The page was served after the refusal.' );
		$this->assertStringContainsString( 'Verification required', $response['body'] );
		$this->assertSame( '60', $response['retry_after'] );
		$this->assertStringContainsString( 'no-store', $response['cache_control'], 'The refusal can be cached, and a cache would go on serving it.' );

		$this->assertStringContainsString(
			sprintf( 'a %s verdict could not be answered (the wp-config.php path reached a %s verdict and let the request continue)', $kind, $kind ),
			$this->logged_since( $offset ),
			'The refusal was not logged.'
		);

		// The report the runner saved before it exited, read back here --
		// past this process's own cache, which remembers the transient as
		// absent from before the other process wrote it.
		wp_cache_flush();

		$report = Diagnostics::recent_anomaly();

		$this->assertNotNull( $report, 'The runner refused the request and saved no report of it.' );
		$this->assertSame( $kind, $report['runner']['early_verdict'] ?? null );
		$this->assertSame( 'evaluation-failed', $report['runner']['failure'] ?? null );
		$this->assertSame( '/bfw-runner-refusal', substr( (string) ( $report['path'] ?? '' ), -strlen( '/bfw-runner-refusal' ) ) );

		// And Site Health raises it, from an administrator's request.
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		$check = Site_Health::check( 'evaluation' );

		$this->assertSame( 'critical', $check['status'], 'Site Health did not raise a refusal the early path left for the runner.' );
		$this->assertStringContainsString( sprintf( 'reached a %s verdict and let the request continue', $kind ), $check['description'] );
		$this->assertStringContainsString( '/bfw-runner-refusal', $check['description'] );
	}

	/**
	 * The verdicts the early path answers itself.
	 *
	 * @return array<string, array{string}>
	 */
	public static function verdicts(): array {
		return array(
			'blocked'   => array( 'blocked' ),
			'challenge' => array( 'challenge' ),
			'redirect'  => array( 'redirect' ),
		);
	}

	/**
	 * A solved challenge is not one of them: it is handed on by design.
	 *
	 * Recorded without the stash that carries it, there is nothing to answer
	 * and nothing to refuse; the tripwire must not fire on it.
	 */
	public function test_a_solved_challenge_is_not_refused(): void {
		$response = $this->request( 'solved' );

		$this->assertSame( 200, $response['status'], 'The runner refused a solved challenge, which the early path hands on by design.' );
		$this->assertStringContainsString( self::SERVED, $response['body'] );
	}

	/**
	 * Request the fixture.
	 *
	 * @param string $verdict The verdict the early path records, or none.
	 *
	 * @return array{status: int, body: string, retry_after: string, cache_control: string}
	 */
	private function request( string $verdict = '' ): array {
		$response = wp_remote_get(
			self::$base . '/bfw-runner-refusal',
			array(
				'timeout'     => 30,
				'redirection' => 0,
				'headers'     => '' === $verdict ? array() : array( 'X-Bfw-Test-Verdict' => $verdict ),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fail( 'The request failed: ' . $response->get_error_message() );
		}

		return array(
			'status'        => (int) wp_remote_retrieve_response_code( $response ),
			'body'          => (string) wp_remote_retrieve_body( $response ),
			'retry_after'   => (string) wp_remote_retrieve_header( $response, 'retry-after' ),
			'cache_control' => (string) wp_remote_retrieve_header( $response, 'cache-control' ),
		);
	}

	/**
	 * The error log's size, so a test reads only what it caused.
	 */
	private function log_size(): int {
		clearstatcache( true, self::$log );

		return is_file( self::$log ) ? (int) filesize( self::$log ) : 0;
	}

	/**
	 * What was logged since an offset.
	 *
	 * @param int $offset Where to start reading.
	 */
	private function logged_since( int $offset ): string {
		clearstatcache( true, self::$log );

		$contents = (string) file_get_contents( self::$log ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the fixture's own error log.

		return substr( $contents, $offset );
	}
}
