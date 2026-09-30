<?php
/**
 * The missing-pass notice in block mode, on the runner's path.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Diagnostics;

/**
 * A visitor whose pass did not come back is told so in `block` mode too (#46).
 *
 * In `block` mode the library answers a solution and writes the interstitial
 * itself, and ends the request, so the plugin can only speak through the
 * library's notice mechanism (kanopi/firewall 2.35.0). Decision_Dispatcher
 * sets the solved marker when the library announces the solve, and adds the
 * notice to the `RequestChallenged` event when the marker arrives without
 * the pass. EarlyPathExceptionModeTest covers the wp-config.php path; this is
 * the runner's, on real WordPress under PHP's built-in web server, behind a
 * router that keeps the early path out of it (fixtures/runner-path.php).
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Decision_Dispatcher
 * @covers \Kanopi\BasicFirewall\Challenge\Pass_Cookie
 */
final class BlockModeNoticeTest extends Settings_Snapshot {

	/**
	 * What the fixture prints once WordPress has let a request through.
	 */
	private const SERVED = 'SERVED BY WORDPRESS';

	/**
	 * A pass cookie name other than the default.
	 */
	private const COOKIE = 'STYXKEY_bfw_notice';

	/**
	 * The notice, as the library writes it.
	 */
	private const NOTICE = 'the verification cookie did not come back';

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
	 * Saved reports, put back afterwards.
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

		$port = (int) substr( $name, (int) strrpos( $name, ':' ) + 1 );
		$home = wp_parse_url( home_url( '/' ) );
		$env  = getenv();
		$env  = array_merge(
			is_array( $env ) ? $env : array(),
			array(
				'BFW_RUNNER_WP_LOAD' => ABSPATH . 'wp-load.php',
				'BFW_RUNNER_HOST'    => (string) ( $home['host'] ?? '' ) . ( isset( $home['port'] ) ? ':' . $home['port'] : '' ),
				'BFW_RUNNER_PATH'    => (string) ( $home['path'] ?? '' ),
			)
		);

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_proc_open -- a test starting a web server, never loaded by a site.
		$process = proc_open(
			array( PHP_BINARY, '-S', '127.0.0.1:' . $port, __DIR__ . '/fixtures/runner-path.php' ),
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

		parent::tearDownAfterClass();
	}

	/**
	 * A block-mode challenge rule, under a pass cookie of its own.
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! is_resource( self::$server ) ) {
			$this->markTestSkipped( 'PHP\'s built-in web server could not be started.' );
		}

		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$this->markTestSkipped( 'BASIC_FIREWALL_MODE pins this site\'s mode, so a fixture cannot choose one.' );
		}

		// The runner saves a report of each request; put the site's back after.
		$this->saved = array(
			'last'    => get_transient( Diagnostics::LAST ),
			'anomaly' => get_transient( Diagnostics::ANOMALY ),
		);

		$this->given_settings(
			array(
				'global'    => array( 'mode' => 'block' ),
				'challenge' => array(
					'provider'    => 'math',
					'secret'      => str_repeat( 'notice-test-secret-', 3 ),
					'cookie_name' => self::COOKIE,
				),
				'rules'     => array(
					array(
						'id'          => 'notice_challenge',
						'type'        => 'url',
						'label'       => 'Notice challenge',
						'enabled'     => true,
						'response'    => 'challenge',
						'weight'      => 0,
						'status_code' => 403,
						'expiration'  => 600,
						'record'      => 'no',
						'settings'    => array(
							'match_type' => 'any',
							'conditions' => array(
								array(
									'variable' => 'path',
									'operator' => 'equals',
									'value'    => '/bfw-notice-match',
								),
							),
						),
					),
				),
			)
		);

		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile.' );
	}

	/**
	 * Put the reports back.
	 */
	protected function tearDown(): void {
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

		parent::tearDown();
	}

	/**
	 * Solve, lose the pass, and be told; keep the pass, and be served.
	 */
	public function test_a_pass_that_did_not_come_back_is_explained(): void {
		$this->assertStringContainsString( self::SERVED, $this->request( '/bfw-notice-other' )['body'], 'The fixture did not reach WordPress, so what follows proves nothing.' );

		$page = $this->request( '/bfw-notice-match' );

		$this->assertStringNotContainsString( self::SERVED, $page['body'], 'The challenged page was served.' );
		$this->assertStringContainsString( 'challenge_state', $page['body'], 'The runner did not serve the library\'s interstitial.' );
		$this->assertStringNotContainsString( self::NOTICE, $page['body'], 'A first challenge carried the missing-pass notice.' );

		$solved = $this->post( '/basic-firewall/challenge', self::solution( $page['body'] ) );
		$pass   = $solved[ self::COOKIE ] ?? '';
		$marker = $solved[ self::COOKIE . '_solved' ] ?? '';

		$this->assertNotSame( '', $pass, 'The library did not issue the pass. Cookies set: ' . implode( ', ', array_keys( $solved ) ) );
		$this->assertMatchesRegularExpression( '/^\d+$/', $marker, 'Solving in block mode set no solved marker. Cookies set: ' . implode( ', ', array_keys( $solved ) ) );

		$lost = $this->request( '/bfw-notice-match', array( 'Cookie' => self::COOKIE . '_solved=' . $marker ) );

		$this->assertStringNotContainsString( self::SERVED, $lost['body'] );
		$this->assertMatchesRegularExpression( '#class="notices".*' . self::NOTICE . '.*<form#s', $lost['body'], 'A visitor whose pass went missing was challenged again without being told.' );

		$kept = $this->request( '/bfw-notice-match', array( 'Cookie' => self::COOKIE . '=' . $pass . '; ' . self::COOKIE . '_solved=' . $marker ) );

		$this->assertStringContainsString( self::SERVED, $kept['body'], 'The pass the library issued was not accepted.' );
	}

	/**
	 * The fields that answer a rendered arithmetic interstitial.
	 *
	 * @param string $page The interstitial.
	 *
	 * @return array<string, string>
	 */
	private static function solution( string $page ): array {
		preg_match_all( '/<input type="hidden" name="([^"]+)" value="([^"]*)">/', $page, $matches, PREG_SET_ORDER );

		$fields = array();

		foreach ( $matches as $match ) {
			$fields[ html_entity_decode( $match[1] ) ] = html_entity_decode( $match[2] );
		}

		$fields['challenge_answer'] = strtok( $fields['challenge_state'] ?? '', '|' );

		return $fields;
	}

	/**
	 * Request the fixture.
	 *
	 * @param string                $path    Path.
	 * @param array<string, string> $headers Headers.
	 *
	 * @return array{status: int, body: string}
	 */
	private function request( string $path, array $headers = array() ): array {
		$response = wp_remote_get(
			self::$base . $path,
			array(
				'timeout'     => 30,
				'redirection' => 0,
				'headers'     => $headers,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fail( 'The request failed: ' . $response->get_error_message() );
		}

		return array(
			'status' => (int) wp_remote_retrieve_response_code( $response ),
			'body'   => (string) wp_remote_retrieve_body( $response ),
		);
	}

	/**
	 * Post a form to the fixture, and return the cookies it set.
	 *
	 * @param string                $path   Path.
	 * @param array<string, string> $fields Form fields.
	 *
	 * @return array<string, string>
	 */
	private function post( string $path, array $fields ): array {
		$response = wp_remote_post(
			self::$base . $path,
			array(
				'timeout'     => 30,
				'redirection' => 0,
				'body'        => $fields,
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->fail( 'The request failed: ' . $response->get_error_message() );
		}

		$cookies = array();

		foreach ( wp_remote_retrieve_cookies( $response ) as $cookie ) {
			$cookies[ $cookie->name ] = $cookie->value;
		}

		return $cookies;
	}
}
