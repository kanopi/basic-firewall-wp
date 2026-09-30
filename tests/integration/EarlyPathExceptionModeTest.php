<?php
/**
 * `exception` mode on the wp-config.php evaluation path.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Runtime\Outcome_Responder;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Runner;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ChallengeSolvedException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
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
	 * A pass cookie name other than the default, set through the settings.
	 */
	private const CUSTOM_COOKIE = 'STYXKEY_bfw_pass';

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
	 * A scratch directory holding the bare plugin copy and the site autoloader.
	 *
	 * @var string
	 */
	private static string $scratch = '';

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

		self::make_scratch_install();

		$env = getenv();
		$env = array_merge(
			is_array( $env ) ? $env : array(),
			array(
				'BFW_EARLY_PLUGIN_PATH'              => dirname( __DIR__, 2 ),
				'BFW_EARLY_PRIVATE_PATH'             => Plugin::instance()->paths()->base(),
				'BFW_EARLY_BARE_PLUGIN_PATH'         => self::$scratch . '/plugin',
				'BFW_EARLY_CUSTOM_AUTOLOADER'        => self::$scratch . '/mu-plugins/vendor/autoload.php',
				'BFW_EARLY_NO_RESPONDER_PLUGIN_PATH' => self::$scratch . '/plugin-no-responder',
				'BFW_EARLY_ERROR_LOG'                => self::$scratch . '/php-error.log',
				'BFW_EARLY_SITE_ROOT'                => self::$scratch . '/site',
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

		if ( '' !== self::$scratch ) {
			// phpcs:disable WordPress.WP.AlternativeFunctions -- a test's own scratch files.
			@unlink( self::$scratch . '/plugin/src' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a symlink, or nothing if it was never made.
			@unlink( self::$scratch . '/php-error.log' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- the fixture's log, or nothing if nothing was logged.
			@unlink( self::$scratch . '/plugin-no-responder/vendor' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/plugin-no-responder' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@unlink( self::$scratch . '/site/vendor/autoload.php' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/site/vendor' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/site/wordpress' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/site' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@unlink( self::$scratch . '/mu-plugins/vendor/autoload.php' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/mu-plugins/vendor' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/mu-plugins' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch . '/plugin' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			@rmdir( self::$scratch ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- as above.
			// phpcs:enable WordPress.WP.AlternativeFunctions

			self::$scratch = '';
		}

		parent::tearDownAfterClass();
	}

	/**
	 * Lay out a site-level Composer install whose vendor-dir is under mu-plugins.
	 *
	 * `plugin/` is the plugin as Composer installs it into a site: its source,
	 * and no vendor/ of its own, because the library is in the site's tree.
	 * Its `src` is a link to the real one, so the bootstrap loads the same
	 * responder and dispatcher it always does.
	 *
	 * `mu-plugins/vendor/autoload.php` is the site's autoloader, at a path the
	 * bootstrap cannot guess. It records that it was loaded and hands on to
	 * this working copy's real autoloader, which carries the library.
	 */
	private static function make_scratch_install(): void {
		$scratch = sys_get_temp_dir() . '/bfw-early-autoloader-' . bin2hex( random_bytes( 4 ) );

		// phpcs:disable WordPress.WP.AlternativeFunctions -- a test's own scratch files, outside WordPress.
		mkdir( $scratch . '/plugin', 0700, true );
		mkdir( $scratch . '/mu-plugins/vendor', 0700, true );
		symlink( dirname( __DIR__, 2 ) . '/src', $scratch . '/plugin/src' );

		// A copy with the library and without src/, so without a responder.
		mkdir( $scratch . '/plugin-no-responder', 0700, true );
		symlink( dirname( __DIR__, 2 ) . '/vendor', $scratch . '/plugin-no-responder/vendor' );
		file_put_contents(
			$scratch . '/mu-plugins/vendor/autoload.php',
			"<?php\n\$GLOBALS['basic_firewall_test_custom_autoloader'] = true;\nreturn require " . var_export( dirname( __DIR__, 2 ) . '/vendor/autoload.php', true ) . ";\n" // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- writing a PHP literal, not debugging.
		);

		/*
		 * A WordPress root with a vendor/ beside it that is not the one the
		 * site loaded: it records being required and carries no library.
		 */
		mkdir( $scratch . '/site/wordpress', 0700, true );
		mkdir( $scratch . '/site/vendor', 0700, true );
		file_put_contents(
			$scratch . '/site/vendor/autoload.php',
			"<?php\n\$GLOBALS['basic_firewall_test_site_autoloader'] = true;\n"
		);
		// phpcs:enable WordPress.WP.AlternativeFunctions

		self::$scratch = $scratch;
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
		$this->assert_no_store( $response );
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
		$this->assert_no_store( $response );
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
		$this->assert_no_store( $response );
	}

	/**
	 * The case in #34: a per-rule ALTCHA challenge on a page WordPress routes.
	 *
	 * `mode: exception`, a `url` rule on a path prefix, `response: challenge`
	 * and the rule naming `altcha` while the site's default provider is
	 * `math`. The report was the page served with WordPress's cache headers
	 * and then cached at the edge, so what is asserted is the whole answer:
	 * the ALTCHA interstitial, a 503, every no-store header a cache in front
	 * of the site might read, and WordPress never reached.
	 */
	public function test_a_per_rule_altcha_challenge_is_served_on_a_routed_page(): void {
		$this->given_rule(
			'challenge',
			'exception',
			array(),
			array(),
			array(
				'challenge_provider' => 'altcha',
				'settings'           => array(
					'match_type' => 'any',
					'conditions' => array(
						array(
							'variable' => 'path',
							'operator' => 'starts_with',
							'value'    => '/learning-resources',
						),
					),
				),
			)
		);

		$response = $this->request( '/learning-resources/some-page/?fresh=' . wp_rand(), array( 'User-Agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36' ) );

		$this->assertStringNotContainsString( self::SERVED, $response['body'], 'The challenged request went on to WordPress.' );
		$this->assertSame( 503, $response['status'], 'A matching request was not challenged on the early path.' );
		$this->assertStringContainsString( 'altcha-widget', $response['body'], 'The rule\'s own provider did not render the interstitial.' );
		$this->assertStringContainsString( 'name="challenge_provider" value="altcha|', $response['body'], 'The signed token does not name the rule\'s provider.' );
		$this->assert_no_store( $response );
	}

	/**
	 * A verdict the responder cannot answer is refused, never served.
	 *
	 * Every way the answer can fail on the early path: the responder throwing,
	 * the responder returning as though the request may continue, and no
	 * responder in this copy of the plugin. Each used to end in the page --
	 * the first two by handing the verdict to a runner that runs after the
	 * page cache, or not at all, and the second by returning the responder's
	 * `true` straight to wp-config.php.
	 *
	 * @dataProvider unanswerable
	 *
	 * @param array<string, string> $headers The scenario's request headers.
	 */
	public function test_a_verdict_the_responder_cannot_answer_is_refused( array $headers ): void {
		$this->given_rule( 'challenge', 'exception' );

		$response = $this->request( '/bfw-early-match', $headers );

		$this->assertStringNotContainsString( self::SERVED, $response['body'], 'A verdict the responder could not answer served the page.' );
		$this->assertSame( 503, $response['status'] );
		$this->assertStringContainsString( 'Verification required', $response['body'] );
		$this->assertSame( '60', $response['retry'] );
		$this->assert_no_store( $response );
	}

	/**
	 * The ways the early path's answer can fail.
	 *
	 * @return array<string, array{0: array<string, string>}>
	 */
	public function unanswerable(): array {
		return array(
			'the responder throws'               => array( array( 'X-Bfw-Test-Responder' => 'throws' ) ),
			'the responder returns'              => array( array( 'X-Bfw-Test-Responder' => 'returns' ) ),
			'there is no responder'              => array( array( 'X-Bfw-Test-Plugin' => 'no-responder' ) ),
			'the verdict is from the other copy' => array( array( 'X-Bfw-Test-Foreign-Verdict' => '1' ) ),
		);
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
		$this->assert_no_store( $response );
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
	 * #35, block mode: the library issues and accepts the configured cookie name.
	 *
	 * Over HTTP, end to end, with the library answering everything itself: the
	 * interstitial, the solution (which sets the pass cookie), and the next
	 * request carrying it. The compiled file is the only place the name comes
	 * from on this path, so what is pinned is that the compiler wrote the
	 * configured name and that the cookie issued under it is the one accepted.
	 */
	public function test_block_mode_issues_and_accepts_the_configured_cookie(): void {
		$this->given_rule( 'challenge', 'block', array(), self::custom_cookie() );

		$this->assertStringContainsString( 'cookie_name: ' . self::CUSTOM_COOKIE, (string) Plugin::instance()->compiled()->contents() );

		$page = $this->request( '/bfw-early-match' );

		$this->assertStringNotContainsString( self::SERVED, $page['body'], 'The challenged page was served.' );

		$solved = $this->post( '/basic-firewall/challenge', self::solution( $page['body'] ) );
		$token  = $solved['cookies'][ self::CUSTOM_COOKIE ] ?? '';

		$this->assertNotSame( '', $token, 'Solving the challenge did not set ' . self::CUSTOM_COOKIE . '. Cookies set: ' . implode( ', ', array_keys( $solved['cookies'] ) ) );
		$this->assertArrayNotHasKey( 'bfw_pass', $solved['cookies'], 'The pass went out under the default name, not the configured one.' );

		$this->assertStringContainsString( self::SERVED, $this->request( '/bfw-early-match', array( 'Cookie' => self::CUSTOM_COOKIE . '=' . $token ) )['body'], 'The pass the library issued was not accepted.' );
		$this->assertStringNotContainsString( self::SERVED, $this->request( '/bfw-early-match', array( 'Cookie' => 'bfw_pass=' . $token ) )['body'], 'The pass was accepted under a name other than the configured one.' );
	}

	/**
	 * #35, exception mode: the runner's cookie is the one the early path reads.
	 *
	 * In exception mode the library hands the solved pass to the plugin, and
	 * the runner sets the cookie. The solution is posted in-process, where the
	 * runner's own cookie list is composed from the compile record, and the
	 * cookie is then presented over HTTP to the wp-config.php path, which
	 * reads only the compiled file.
	 */
	public function test_exception_mode_issues_and_accepts_the_configured_cookie(): void {
		$this->given_rule( 'challenge', 'exception', array(), self::custom_cookie() );

		$firewall = Firewall::create( array( Plugin::instance()->paths()->compiled_file() ) );

		try {
			$firewall->evaluate( Request::create( '/bfw-early-match' ) );
			$this->fail( 'The matching request was not challenged.' );
		} catch ( ChallengeRequiredException $challenge ) {
			$page = $challenge->renderInterstitial( Request::create( '/bfw-early-match' ) );
		}

		try {
			$firewall->evaluate( Request::create( '/basic-firewall/challenge', 'POST', self::solution( $page ) ) );
			$this->fail( 'The solution was not accepted.' );
		} catch ( ChallengeSolvedException $solved ) {
			$cookies = Outcome_Responder::solved_cookies( $solved->getToken(), Plugin::instance()->compiled()->pass_cookie(), false );
		}

		$this->assertSame( self::CUSTOM_COOKIE, $cookies[0]['name'], 'The runner would set the pass under a name other than the compiled one.' );
		$this->assertSame( self::CUSTOM_COOKIE . '_solved', $cookies[1]['name'], 'The solved marker is not named after the pass cookie.' );

		$pass = $cookies[0]['name'] . '=' . $cookies[0]['value'];

		$this->assertTrue( $firewall->evaluate( Request::create( '/bfw-early-match', 'GET', array(), array( $cookies[0]['name'] => $cookies[0]['value'] ) ) ), 'The normal path refused the pass it issued.' );
		$this->assertStringContainsString( self::SERVED, $this->request( '/bfw-early-match', array( 'Cookie' => $pass ) )['body'], 'The early path refused the pass the runner issued.' );
		$this->assertStringNotContainsString( self::SERVED, $this->request( '/bfw-early-match', array( 'Cookie' => 'bfw_pass=' . $cookies[0]['value'] ) )['body'], 'The early path accepted the pass under a name other than the configured one.' );

		// And the safeguard: solved a moment ago, but the pass did not come back.
		$lost = $this->request( '/bfw-early-match', array( 'Cookie' => $cookies[1]['name'] . '=' . time() ) );

		$this->assertSame( 503, $lost['status'] );
		$this->assertStringContainsString( 'bfw-missing-pass', $lost['body'], 'A visitor whose pass went missing was challenged again without being told.' );
		$this->assert_no_store( $lost );
		$this->assertStringNotContainsString( 'bfw-missing-pass', $this->request( '/bfw-early-match' )['body'], 'A first challenge carried the missing-pass notice.' );
	}

	/**
	 * A challenge section whose pass cookie is set to CUSTOM_COOKIE, as the
	 * Challenge screen's field would store it.
	 *
	 * @return array<string, mixed>
	 */
	private static function custom_cookie(): array {
		return array(
			'challenge' => array(
				'provider'    => 'math',
				'secret'      => str_repeat( 'early-path-secret-', 3 ),
				'cookie_name' => self::CUSTOM_COOKIE,
			),
		);
	}

	/**
	 * The fields that answer a rendered arithmetic interstitial correctly.
	 *
	 * The math provider signs `answer|expiry` into a hidden field, so the
	 * expected answer is readable from the page -- the signature, not secrecy,
	 * is what stops it being altered.
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
	 * Post a form to the fixture.
	 *
	 * @param string                $path   Path to post to.
	 * @param array<string, string> $fields Form fields.
	 *
	 * @return array{status: int, cookies: array<string, string>}
	 */
	private function post( string $path, array $fields ): array {
		$response = wp_remote_post(
			self::$base . $path,
			array(
				'timeout'     => 15,
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

		return array(
			'status'  => (int) wp_remote_retrieve_response_code( $response ),
			'cookies' => $cookies,
		);
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
	 * With a role exempt, a request carrying a login cookie waits for the runner.
	 *
	 * Whose the cookie is can only be known once WordPress validates it, so
	 * this path leaves the request unmarked and the runner decides. Without
	 * the cookie, or with no role exempt, nothing changes.
	 */
	public function test_a_login_cookie_waits_for_the_runner_when_a_role_is_exempt(): void {
		$cookie = array( 'Cookie' => 'wordpress_logged_in_0123abcd=someone%7C1%7Cforged' );

		$this->given_rule( 'block', 'block' );

		$this->assertSame( 403, $this->request( '/bfw-early-match', $cookie )['status'], 'With no role exempt, a login cookie changed where the request was evaluated.' );

		$this->given_rule( 'block', 'block', array( 'bypass_roles' => array( 'editor' ) ) );

		$this->assertSame( 403, $this->request( '/bfw-early-match' )['status'], 'An exempt role stopped this path evaluating requests that carry no login cookie.' );

		$response = $this->request( '/bfw-early-match', $cookie );

		$this->assertSame( 200, $response['status'] );
		$this->assertSame( 'deferred-login', $response['reason'] );
		$this->assertSame( 'no', $response['evaluated'], 'The request was marked evaluated, so the runner would never check the cookie or evaluate it.' );
	}

	/**
	 * A failure that is not a verdict fails open, and is reported.
	 *
	 * It used to fail open silently on both paths: nothing recorded that the
	 * request had gone through unfiltered, so Site Health reported a healthy
	 * firewall on the very request it had just waved through.
	 */
	public function test_a_failure_fails_open_and_is_reported(): void {
		$GLOBALS['basic_firewall_early'] = array(
			'called'    => true,
			'evaluated' => true,
		);

		$log      = (string) tempnam( sys_get_temp_dir(), 'bfw-log' );
		$previous = ini_set( 'error_log', $log ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- captured for the assertion below, and put back.

		try {
			$this->assertTrue(
				basic_firewall_answer_outcome( new \RuntimeException( 'the evaluator broke' ), null, basic_firewall_options( array( 'plugin_path' => dirname( __DIR__, 2 ) ) ) ),
				'A failure of the firewall refused the request instead of failing open.'
			);
		} finally {
			ini_set( 'error_log', (string) $previous ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- put back.
		}

		$logged = (string) file_get_contents( $log ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the log captured above.

		wp_delete_file( $log );

		$this->assertStringContainsString( 'Basic Firewall [warning]: fail-open (early)', $logged, 'The fail-open was not logged.' );
		$this->assertStringContainsString( 'EarlyPathExceptionModeTest.php:', $logged, 'The log line does not say where the failure was thrown.' );
		$this->assertStringContainsString( 'EarlyPathExceptionModeTest.php:', (string) ( $GLOBALS['basic_firewall_early']['failure_origin'] ?? '' ) );

		$this->assertStringContainsString( 'the evaluator broke', (string) ( $GLOBALS['basic_firewall_early']['failure'] ?? '' ), 'The bootstrap did not record the failure.' );

		Runner::reset();

		try {
			// The runner takes it up when WordPress loads: this process has
			// BASIC_FIREWALL_EVALUATED defined, as the bootstrap leaves it.
			$this->assertTrue( ( new Runner() )->evaluate() );
			$this->assertStringContainsString( 'the evaluator broke', (string) Runner::failure(), 'The runner did not take up the failure, so nothing reports it.' );
			$this->assertSame( 'critical', Site_Health::check( 'compiled' )['status'] );
		} finally {
			Runner::reset();
		}
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
			'Exception mode cannot answer challenges, redirects or blocks properly on the wp-config.php path',
			Site_Health::check( 'evaluation' )['label']
		);
	}

	/**
	 * A vendor-dir the bootstrap cannot guess, named by the option, is evaluated early.
	 *
	 * The case in #26: the plugin has no vendor/ of its own, and the site's
	 * tree is under mu-plugins. It used to end in `no-autoloader`, every
	 * time, and be evaluated after advanced-cache.php.
	 */
	public function test_an_autoloader_named_by_the_option_is_evaluated(): void {
		$this->given_rule( 'block', 'block' );

		$response = $this->request( '/bfw-early-match', array( 'X-Bfw-Test-Plugin' => 'bare' ) );

		$this->assertSame( 'no-autoloader', $response['reason'], 'The bare copy found an autoloader without being told, so the tests below prove nothing.' );
		$this->assertSame( 200, $response['status'] );

		$response = $this->request(
			'/bfw-early-match',
			array(
				'X-Bfw-Test-Plugin'     => 'bare',
				'X-Bfw-Test-Autoloader' => 'option',
			)
		);

		$this->assertSame( 403, $response['status'], 'The autoloader the snippet named was not used to evaluate the request.' );

		// A refusal ends the request before the fixture's report headers, so
		// which autoloader was used is read off one the rule lets through.
		$allowed = $this->request_with_autoloader( 'bare', 'option' );

		$this->assertSame( 'yes', $allowed['evaluated'] );
		$this->assertSame( 'option', $allowed['autoloader'] );
		$this->assertSame( 'yes', $allowed['custom'] );
	}

	/**
	 * BASIC_FIREWALL_AUTOLOADER names it once per environment, to the same effect.
	 */
	public function test_an_autoloader_named_by_the_constant_is_evaluated(): void {
		$this->given_rule( 'block', 'block' );

		$response = $this->request(
			'/bfw-early-match',
			array(
				'X-Bfw-Test-Plugin'     => 'bare',
				'X-Bfw-Test-Autoloader' => 'constant',
			)
		);

		$this->assertSame( 403, $response['status'], 'The autoloader BASIC_FIREWALL_AUTOLOADER named was not used.' );

		$allowed = $this->request_with_autoloader( 'bare', 'constant' );

		$this->assertSame( 'constant', $allowed['autoloader'] );
		$this->assertSame( 'yes', $allowed['custom'] );
	}

	/**
	 * The option beats the constant, as every other bootstrap option does.
	 */
	public function test_the_option_beats_the_constant(): void {
		$this->given_rule( 'block', 'block' );

		$response = $this->request(
			'/bfw-early-match',
			array(
				'X-Bfw-Test-Plugin'     => 'bare',
				'X-Bfw-Test-Autoloader' => 'both',
			)
		);

		$this->assertSame( 403, $response['status'], 'A constant naming a missing file overrode the snippet\'s own autoloader.' );
		$this->assertSame( 'option', $this->request_with_autoloader( 'bare', 'both' )['autoloader'] );
	}

	/**
	 * A named autoloader that is not there is said out loud, not guessed past.
	 *
	 * Falling through to the guessed locations would report `no-autoloader`
	 * about a site that did name one, or run the firewall from a tree nobody
	 * chose. The request goes on unevaluated, for the mu-plugin -- and the
	 * reason names the file, on every screen that reports it.
	 */
	public function test_an_unreadable_autoloader_is_reported_and_not_evaluated(): void {
		$this->given_rule( 'block', 'block' );

		foreach ( array(
			'missing'          => 'option',
			'missing-constant' => 'constant',
		) as $scenario => $source ) {
			$response = $this->request(
				'/bfw-early-match',
				array(
					'X-Bfw-Test-Plugin'     => 'bare',
					'X-Bfw-Test-Autoloader' => $scenario,
				)
			);

			$this->assertSame( 200, $response['status'], 'A request was refused with no library to refuse it.' );
			$this->assertStringContainsString( self::SERVED, $response['body'] );
			$this->assertSame( 'autoloader-unreadable', $response['reason'] );
			$this->assertSame( 'no', $response['evaluated'], 'The request was marked evaluated, so the mu-plugin would not evaluate it either.' );
			$this->assertSame( 'unreadable', $response['autoloader'] );
			$this->assertStringEndsWith( '/not-here/autoload.php', $response['autoloader_file'] );
			$this->assertSame( $source, $response['autoloader_named'] );

			// What the status screens make of it.
			$GLOBALS['basic_firewall_early'] = array(
				'called'      => true,
				'credentials' => true,
				'evaluated'   => false,
				'reason'      => 'autoloader-unreadable',
				'responder'   => true,
				'autoloader'  => array(
					'source' => 'unreadable',
					'file'   => $response['autoloader_file'],
					'named'  => $response['autoloader_named'],
				),
			);

			$check = Site_Health::check( 'evaluation' );

			$this->assertSame( 'critical', $check['status'], 'Site Health did not report an early path that evaluates nothing.' );
			$this->assertStringContainsString( esc_html( $response['autoloader_file'] ), $check['description'], 'The report does not say which file could not be read.' );
			$this->assertStringContainsString( 'basic_firewall_evaluate(', $check['description'], 'The report does not show the snippet to correct.' );

			$text = Site_Health::early_reason_text( 'autoloader-unreadable' );

			$this->assertStringContainsString( $response['autoloader_file'], $text );
			$this->assertStringContainsString( 'constant' === $source ? 'BASIC_FIREWALL_AUTOLOADER' : "'autoloader' option", $text, 'The report does not say where the path was named.' );
		}
	}

	/**
	 * A site that required its own autoloader above the snippet is evaluated with it.
	 *
	 * Nothing for the bootstrap to require, and nothing named -- but the
	 * library is loadable, so there is no reason to give up.
	 */
	public function test_a_library_loaded_before_the_snippet_is_evaluated(): void {
		$this->given_rule( 'block', 'block' );

		$response = $this->request(
			'/bfw-early-match',
			array(
				'X-Bfw-Test-Plugin'     => 'bare',
				'X-Bfw-Test-Autoloader' => 'preloaded',
			)
		);

		$this->assertSame( 403, $response['status'], 'A library wp-config.php had already loaded was not used.' );

		$allowed = $this->request_with_autoloader( 'bare', 'preloaded' );

		$this->assertSame( 'loaded', $allowed['autoloader'] );
		$this->assertSame( 'yes', $allowed['evaluated'] );
	}

	/**
	 * A library already loaded is used before a vendor/ beside the WordPress root (#44).
	 *
	 * The site required its own autoloader above the snippet, and a different
	 * vendor/ sits where the bootstrap guesses. Requiring that second one as
	 * well would register two Composer trees, and classes could then resolve
	 * from either -- the mixed copy the scoped-first rule exists to prevent.
	 * So it must never be required, and the request is still evaluated, with
	 * the library the site loaded.
	 */
	public function test_a_loaded_library_beats_a_vendor_dir_beside_the_root(): void {
		$this->given_rule( 'block', 'block' );

		$headers = array(
			'X-Bfw-Test-Plugin'     => 'bare',
			'X-Bfw-Test-Autoloader' => 'preloaded-beside-site',
		);

		$this->assertSame( 403, $this->request( '/bfw-early-match', $headers )['status'], 'The library the site loaded was not used to evaluate.' );

		$allowed = $this->request_with_autoloader( 'bare', 'preloaded-beside-site' );

		$this->assertSame( 'loaded', $allowed['autoloader'] );
		$this->assertSame( '', $allowed['autoloader_file'], 'A file was required although the library was already loadable.' );
		$this->assertSame( 'yes', $allowed['evaluated'] );
		$this->assertSame( 'yes', $allowed['custom'], 'The fixture did not preload the site\'s autoloader.' );
		$this->assertSame( 'no', $allowed['site'], 'The vendor/ beside the WordPress root was required on top of the loaded library.' );

		// The plugin's own vendor/ still comes first, preloaded library or not.
		$own = $this->request_with_autoloader( '', 'preloaded-beside-site' );

		$this->assertSame( 'plugin', $own['autoloader'] );
		$this->assertSame( 'no', $own['site'] );
	}

	/**
	 * The plugin's own vendor/ still wins over an autoloader the site names.
	 *
	 * A release zip carries the library scoped, and its compiled file names
	 * the scoped classes: built from any other copy, the firewall cannot read
	 * its own configuration. So a site naming its autoloader -- for a vendor
	 * tree that happens to carry kanopi/firewall for some other reason --
	 * must not change which copy a release build runs.
	 */
	public function test_the_plugins_own_vendor_wins_over_a_named_autoloader(): void {
		$this->given_rule( 'block', 'block' );

		foreach ( array( 'option', 'constant' ) as $scenario ) {
			$this->assertSame( 403, $this->request( '/bfw-early-match', array( 'X-Bfw-Test-Autoloader' => $scenario ) )['status'] );

			$allowed = $this->request_with_autoloader( '', $scenario );

			$this->assertSame( 'plugin', $allowed['autoloader'], 'A named autoloader was preferred to the plugin\'s own vendor/.' );
			$this->assertSame( 'no', $allowed['custom'], 'The site\'s autoloader was loaded although the plugin\'s own was there.' );
		}
	}

	/**
	 * A failure on the early path fails open, and is logged -- every time.
	 *
	 * The report it leaves reaches Site Health only on the request it
	 * happened on, which is a visitor's. #34 was a firewall failing on
	 * visitors' requests with nothing in the PHP error log.
	 */
	public function test_a_failure_on_the_early_path_is_logged(): void {
		$this->given_rule( 'challenge', 'exception' );

		$log = $this->error_log();

		$response = $this->request( '/bfw-early-match', array( 'X-Bfw-Test-Throw' => 'evaluate' ) );

		$this->assertSame( 200, $response['status'], 'A failure of the firewall refused the request instead of failing open.' );
		$this->assertStringContainsString( self::SERVED, $response['body'] );

		$lines = $this->logged_since( $log, 'fail-open (early)' );

		$this->assertCount( 1, $lines, 'The fail-open was not logged exactly once.' );
		$this->assertStringContainsString( 'Basic Firewall [warning]: fail-open (early)', $lines[0] );
		$this->assertStringContainsString( 'RuntimeException', $lines[0], 'The log line does not name the exception class.' );
		$this->assertStringContainsString( 'the fixture broke evaluation', $lines[0], 'The log line does not carry the message.' );
		$this->assertMatchesRegularExpression( '/fake-request-factory\.php:\d+/', $lines[0], 'The log line does not say where it was thrown.' );
		$this->assertStringNotContainsString( 'hunter2', $lines[0], 'A password in a DSN reached the log.' );
		$this->assertStringNotContainsString( '#0 ', $lines[0], 'A trace was logged rather than the origin.' );

		// And again on the next request: a failure is logged every time.
		$this->request( '/bfw-early-match', array( 'X-Bfw-Test-Throw' => 'evaluate' ) );

		$this->assertCount( 2, $this->logged_since( $log, 'fail-open (early)' ) );
	}

	/**
	 * An early path that does not evaluate says so, at most once per interval.
	 *
	 * A misconfiguration is the same on every request, so it is logged once
	 * and then left quiet, across requests and processes. The reasons that
	 * are the configuration working as meant are not logged at all.
	 */
	public function test_a_not_evaluated_warning_is_logged_once_per_interval(): void {
		$this->given_rule( 'block', 'block' );

		$marker = Plugin::instance()->paths()->base() . '/.warned-no-autoloader';

		wp_delete_file( $marker );

		try {
			$log = $this->error_log();

			$this->assertSame( 'no-autoloader', $this->request( '/bfw-early-other', array( 'X-Bfw-Test-Plugin' => 'bare' ) )['reason'] );
			$this->assertSame( 'no-autoloader', $this->request( '/bfw-early-other', array( 'X-Bfw-Test-Plugin' => 'bare' ) )['reason'] );

			$lines = $this->logged_since( $log, 'not-evaluated (early)' );

			$this->assertCount( 1, $lines, 'The warning was not logged exactly once for two requests.' );
			$this->assertStringContainsString( 'Basic Firewall [warning]: not-evaluated (early)', $lines[0] );
			$this->assertStringContainsString( '(no-autoloader)', $lines[0] );
			$this->assertFileExists( $marker, 'The interval is not remembered anywhere another process can see.' );

			// Once the interval has passed, it is logged again.
			touch( $marker, time() - 3600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- ageing the bootstrap's own marker file.
			clearstatcache();

			$this->request( '/bfw-early-other', array( 'X-Bfw-Test-Plugin' => 'bare' ) );

			$this->assertCount( 2, $this->logged_since( $log, 'not-evaluated (early)' ) );

			// A request handed to the runner on purpose is not a warning.
			$this->given_rule( 'block', 'block', array( 'bypass_roles' => array( 'editor' ) ) );

			$deferred = $this->request( '/bfw-early-other', array( 'Cookie' => 'wordpress_logged_in_0123abcd=someone%7C1%7Cforged' ) );

			$this->assertSame( 'deferred-login', $deferred['reason'] );
			$this->assertCount( 2, $this->logged_since( $log, 'not-evaluated (early)' ), 'A deferred login was logged as a problem.' );
		} finally {
			wp_delete_file( $marker );
		}
	}

	/**
	 * BASIC_FIREWALL_DEBUG adds the report header; without it there is none.
	 */
	public function test_the_debug_header_is_only_sent_when_asked_for(): void {
		$this->given_rule( 'challenge', 'exception' );

		$this->assertSame( '', $this->request( '/bfw-early-match' )['debug'], 'The debug header was sent without BASIC_FIREWALL_DEBUG.' );
		$this->assertSame( '', $this->request( '/bfw-early-other' )['debug'], 'The debug header was sent without BASIC_FIREWALL_DEBUG.' );

		// On a response the bootstrap writes itself.
		$challenged = $this->request( '/bfw-early-match', array( 'X-Bfw-Test-Debug' => '1' ) );

		$this->assertSame( 503, $challenged['status'] );

		$report = json_decode( $challenged['debug'], true );

		$this->assertIsArray( $report, 'The debug header is not JSON: ' . $challenged['debug'] );
		$this->assertTrue( $report['early']['called'] );
		$this->assertTrue( $report['early']['evaluated'] );
		$this->assertSame( 'challenge', $report['early']['outcome'] );
		$this->assertSame( 'exception', $report['early']['mode'], 'The header does not say which mode the web request was evaluated in.' );
		$this->assertSame( 'plugin', $report['early']['autoloader'] );
		$this->assertStringNotContainsString( Plugin::instance()->paths()->base(), $challenged['debug'], 'The header gives away the private directory.' );

		// On a request that goes on to WordPress.
		$allowed = json_decode( $this->request( '/bfw-early-other', array( 'X-Bfw-Test-Debug' => '1' ) )['debug'], true );

		$this->assertTrue( $allowed['early']['evaluated'] );
		$this->assertNull( $allowed['early']['outcome'] );

		// On one the early path did not evaluate, with the reason.
		$skipped = json_decode(
			$this->request(
				'/bfw-early-other',
				array(
					'X-Bfw-Test-Debug'  => '1',
					'X-Bfw-Test-Plugin' => 'bare',
				)
			)['debug'],
			true
		);

		$this->assertFalse( $skipped['early']['evaluated'] );
		$this->assertSame( 'no-autoloader', $skipped['early']['reason'] );

		// And on a failure, by class and file name only.
		$failed = json_decode(
			$this->request(
				'/bfw-early-match',
				array(
					'X-Bfw-Test-Debug' => '1',
					'X-Bfw-Test-Throw' => 'evaluate',
				)
			)['debug'],
			true
		);

		$this->assertStringStartsWith( 'RuntimeException @ fake-request-factory.php:', (string) $failed['early']['failure'] );
	}

	/**
	 * A rule the early path's firewall could not construct is recorded (#41).
	 *
	 * The library skips such a rule and goes on, so the request it would
	 * have refused is served -- and before this, nothing a status screen
	 * could read said so.
	 */
	public function test_failed_rules_on_the_early_path_are_recorded(): void {
		$this->given_rule( 'block', 'block' );

		$healthy = $this->request( '/bfw-early-other' );

		$this->assertSame( 'none', $healthy['failed_rules'], 'A firewall whose rules all built reported a failed one.' );

		$broken = $this->request(
			'/bfw-early-match',
			array(
				'X-Bfw-Test-Failed-Rule' => '1',
				'X-Bfw-Test-Debug'       => '1',
			)
		);

		$this->assertSame( 200, $broken['status'], 'The fixture\'s rule still ran, so nothing failed to construct.' );
		$this->assertSame( 'block/Reputation:0', $broken['failed_rules'] );
		$this->assertSame( 'yes', $broken['evaluated'] );

		$report = json_decode( $broken['debug'], true );

		$this->assertIsArray( $report );
		$this->assertSame( array( 'block/Reputation:0' ), $report['early']['failed_rules'], 'The debug header does not name the rule.' );
		$this->assertStringNotContainsString( 'upstream', $broken['debug'], 'The constructor\'s message reached the header.' );

		// Not evaluated here, so nothing to say rather than nothing failed.
		$this->assertSame( 'unknown', $this->request( '/bfw-early-other', array( 'X-Bfw-Test-Plugin' => 'bare' ) )['failed_rules'] );
	}

	/**
	 * Where the fixture's PHP error log ends now, to read what follows.
	 */
	private function error_log(): int {
		clearstatcache();

		$file = self::$scratch . '/php-error.log';

		return is_readable( $file ) ? (int) filesize( $file ) : 0;
	}

	/**
	 * Lines logged since an offset that contain a string.
	 *
	 * @param int    $offset Where to start reading.
	 * @param string $needle What the lines must contain.
	 *
	 * @return list<string>
	 */
	private function logged_since( int $offset, string $needle ): array {
		clearstatcache();

		$file = self::$scratch . '/php-error.log';

		if ( ! is_readable( $file ) ) {
			return array();
		}

		$logged = (string) file_get_contents( $file, false, null, $offset ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the fixture's log file.

		return array_values( array_filter( explode( "\n", $logged ), static fn ( string $line ): bool => str_contains( $line, $needle ) ) );
	}

	/**
	 * Assert a response carries the whole no-store set, from kanopi/firewall#418.
	 *
	 * @param array<string, mixed> $response A response from request().
	 */
	private function assert_no_store( array $response ): void {
		$this->assertSame( 'private, no-store, no-cache, must-revalidate, max-age=0', $response['cache'], 'Cache-Control is not the full no-store value.' );
		$this->assertSame( 'no-cache', $response['pragma'] );
		$this->assertSame( '0', $response['expires'] );
		$this->assertSame( 'no-store', $response['surrogate'], 'A surrogate cache is not told to keep this out.' );
		$this->assertSame( 'no-store', $response['cdn'], 'A CDN is not told to keep this out.' );
	}

	/**
	 * Install one URL rule matching /bfw-early-match, and compile it.
	 *
	 * @param string               $response Rule response.
	 * @param string               $mode     Operating mode.
	 * @param array<string, mixed> $extra    Further global settings.
	 * @param array<string, mixed> $document Further top-level settings.
	 * @param array<string, mixed> $rule     Replacements for the rule's own fields.
	 */
	private function given_rule( string $response, string $mode, array $extra = array(), array $document = array(), array $rule = array() ): void {
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
					array_replace(
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
						$rule
					),
				),
			)
		);

		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The fixture did not compile.' );
		$this->assertSame( array(), $result['problems'], 'The fixture compiled with problems.' );
	}

	/**
	 * Request a path no rule matches, as a given install.
	 *
	 * @param string $plugin     `bare` for the copy with no vendor/, or empty for this one.
	 * @param string $autoloader The fixture's autoloader scenario.
	 *
	 * @return array{status: int, body: string, type: string, cache: string, location: string, retry: string, stashed: string, outcome: string, reason: string, evaluated: string, autoloader: string, autoloader_file: string, autoloader_named: string, custom: string, site: string, failed_rules: string, pragma: string, expires: string, surrogate: string, cdn: string, debug: string}
	 */
	private function request_with_autoloader( string $plugin, string $autoloader ): array {
		$response = $this->request(
			'/bfw-early-other',
			array(
				'X-Bfw-Test-Plugin'     => $plugin,
				'X-Bfw-Test-Autoloader' => $autoloader,
			)
		);

		$this->assertSame( 200, $response['status'], 'A request no rule matches was refused.' );

		return $response;
	}

	/**
	 * Make a request of the fixture.
	 *
	 * @param string                $path    Path to request.
	 * @param array<string, string> $headers Request headers.
	 *
	 * @return array{status: int, body: string, type: string, cache: string, location: string, retry: string, stashed: string, outcome: string, reason: string, evaluated: string, autoloader: string, autoloader_file: string, autoloader_named: string, custom: string, site: string, failed_rules: string, pragma: string, expires: string, surrogate: string, cdn: string, debug: string}
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
			'status'           => (int) wp_remote_retrieve_response_code( $response ),
			'body'             => (string) wp_remote_retrieve_body( $response ),
			'type'             => (string) wp_remote_retrieve_header( $response, 'content-type' ),
			'cache'            => (string) wp_remote_retrieve_header( $response, 'cache-control' ),
			'location'         => (string) wp_remote_retrieve_header( $response, 'location' ),
			'retry'            => (string) wp_remote_retrieve_header( $response, 'retry-after' ),
			'stashed'          => (string) wp_remote_retrieve_header( $response, 'x-early-stashed' ),
			'outcome'          => (string) wp_remote_retrieve_header( $response, 'x-early-outcome' ),
			'reason'           => (string) wp_remote_retrieve_header( $response, 'x-early-reason' ),
			'evaluated'        => (string) wp_remote_retrieve_header( $response, 'x-early-evaluated' ),
			'autoloader'       => (string) wp_remote_retrieve_header( $response, 'x-early-autoloader' ),
			'autoloader_file'  => (string) wp_remote_retrieve_header( $response, 'x-early-autoloader-file' ),
			'autoloader_named' => (string) wp_remote_retrieve_header( $response, 'x-early-autoloader-named' ),
			'custom'           => (string) wp_remote_retrieve_header( $response, 'x-early-custom-loaded' ),
			'site'             => (string) wp_remote_retrieve_header( $response, 'x-early-site-loaded' ),
			'failed_rules'     => (string) wp_remote_retrieve_header( $response, 'x-early-failed-rules' ),
			'pragma'           => (string) wp_remote_retrieve_header( $response, 'pragma' ),
			'expires'          => (string) wp_remote_retrieve_header( $response, 'expires' ),
			'surrogate'        => (string) wp_remote_retrieve_header( $response, 'surrogate-control' ),
			'cdn'              => (string) wp_remote_retrieve_header( $response, 'cdn-cache-control' ),
			'debug'            => (string) wp_remote_retrieve_header( $response, 'x-basic-firewall-early' ),
		);
	}
}
