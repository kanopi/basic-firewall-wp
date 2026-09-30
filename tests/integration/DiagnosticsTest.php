<?php
/**
 * Diagnostics for the evaluation paths: fail-open logging and the saved report.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Runtime\Diagnostics;
use Kanopi\BasicFirewall\Runtime\Runner;
use Symfony\Component\HttpFoundation\Request;

/**
 * A firewall that fails open says so, and the last web request is readable later.
 *
 * #34: on a host with several web containers and WP-CLI in another, a
 * challenge rule served the page in `exception` mode with nothing logged, and
 * every status screen described its own request rather than the visitor's.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Diagnostics
 * @covers \Kanopi\BasicFirewall\Runtime\Runner
 * @covers \Kanopi\BasicFirewall\Health\Site_Health
 */
final class DiagnosticsTest extends Settings_Snapshot {

	/**
	 * State this test replaces, put back afterwards.
	 *
	 * @var array<string, mixed>
	 */
	private array $saved = array();

	/**
	 * The PHP error log, captured to a file.
	 *
	 * @var string
	 */
	private string $log = '';

	/**
	 * Save what the test changes, and capture the error log.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->saved = array(
			'early'     => $GLOBALS['basic_firewall_early'] ?? null,
			'server'    => $_SERVER,
			'last'      => get_transient( Diagnostics::LAST ),
			'anomaly'   => get_transient( Diagnostics::ANOMALY ),
			'error_log' => (string) ini_get( 'error_log' ),
		);

		$this->log = (string) tempnam( sys_get_temp_dir(), 'bfw-diagnostics' );

		ini_set( 'error_log', $this->log ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- captured for assertions, and put back.

		Runner::reset();
		Diagnostics::reset_throttle();
	}

	/**
	 * Put it all back.
	 */
	protected function tearDown(): void {
		ini_set( 'error_log', $this->saved['error_log'] ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- put back.
		wp_delete_file( $this->log );

		$GLOBALS['basic_firewall_early'] = $this->saved['early'];
		$_SERVER                         = $this->saved['server'];

		foreach ( array(
			Diagnostics::LAST    => 'last',
			Diagnostics::ANOMALY => 'anomaly',
		) as $transient => $key ) {
			if ( false === $this->saved[ $key ] ) {
				delete_transient( $transient );
			} else {
				set_transient( $transient, $this->saved[ $key ], Diagnostics::TTL );
			}
		}

		Runner::reset();
		Diagnostics::reset_throttle();

		parent::tearDown();
	}

	/**
	 * A failure partway through evaluating fails open on the runner path, and is logged.
	 */
	public function test_a_runner_evaluation_failure_is_logged(): void {
		$this->given_exception_mode();

		$request = new class() extends Request {
			/**
			 * Fail the way a firewall failing partway through would.
			 *
			 * @throws \LogicException Always.
			 */
			public function getPathInfo(): string {
				throw new \LogicException( 'the runner fixture broke' );
			}
		};

		$this->assertTrue( $this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), $request ), 'A failure refused the request instead of failing open.' );

		$logged = $this->logged();

		$this->assertStringContainsString( 'Basic Firewall [warning]: fail-open (runner)', $logged, 'The runner failed open without logging it.' );
		$this->assertStringContainsString( 'LogicException', $logged );
		$this->assertStringContainsString( 'the runner fixture broke', $logged );
		$this->assertStringContainsString( 'DiagnosticsTest.php:', $logged, 'The log line does not say where it was thrown.' );
		$this->assertSame( 'evaluation-failed', Runner::state()['failure'] );
		$this->assertTrue( Runner::state()['evaluated'] );
		$this->assertSame( 'exception', Runner::state()['mode'] );
	}

	/**
	 * A firewall that cannot start fails open on the runner path, and is logged.
	 */
	public function test_a_runner_that_cannot_start_is_logged(): void {
		// A configuration input that is not there, with require_config on:
		// the library refuses to start rather than run a partial ruleset.
		$require = static fn ( array $overrides ): array => array( '[global][require_config]' => true ) + $overrides;

		add_filter( 'basic_firewall_config_overrides', $require );

		try {
			$this->assertTrue( $this->evaluate_compiled( sys_get_temp_dir() . '/bfw-not-there-' . wp_rand() . '.yml', Request::create( '/anything' ) ) );
		} finally {
			remove_filter( 'basic_firewall_config_overrides', $require );
		}

		$this->assertStringContainsString( 'Basic Firewall [warning]: fail-open (runner): the firewall could not start', $this->logged() );
		$this->assertSame( 'could-not-start', Runner::state()['failure'] );
		$this->assertFalse( Runner::state()['evaluated'] );
	}

	/**
	 * An allowed request is recorded as evaluated and allowed, with nothing logged.
	 */
	public function test_an_allowed_request_is_recorded_and_not_logged(): void {
		$this->given_exception_mode();

		$this->assertTrue( $this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), Request::create( '/nothing-matches-this' ) ) );

		$this->assertSame( '', $this->logged() );
		$this->assertSame( 'allowed', Runner::state()['outcome'] );
		$this->assertNull( Runner::state()['failure'] );
	}

	/**
	 * The last request and the last anomaly are kept apart.
	 */
	public function test_the_last_anomaly_survives_ordinary_requests(): void {
		$this->given_early( array( 'reason' => 'no-autoloader' ) );

		Diagnostics::persist();

		$anomaly = Diagnostics::last_anomaly();

		$this->assertIsArray( $anomaly );
		$this->assertSame( 'not-evaluated', $anomaly['anomaly'] );
		$this->assertSame( 'no-autoloader', $anomaly['early']['reason'] );
		$this->assertSame( $anomaly, Diagnostics::last() );

		// An ordinary request afterwards replaces the last one only.
		Diagnostics::reset_throttle();

		$this->given_early( array( 'evaluated' => true ) );

		Diagnostics::persist();

		$last = Diagnostics::last();

		$this->assertIsArray( $last );
		$this->assertTrue( $last['early']['evaluated'], 'The ordinary request was not saved as the last one.' );
		$this->assertNull( $last['anomaly'] );
		$this->assertSame( 'no-autoloader', Diagnostics::last_anomaly()['early']['reason'] ?? null, 'An ordinary request overwrote the anomaly.' );
	}

	/**
	 * Writes are throttled, so a busy site does not write on every request.
	 */
	public function test_writes_are_throttled(): void {
		$this->given_early( array( 'evaluated' => true ) );

		$_SERVER['REQUEST_URI'] = '/first';

		Diagnostics::persist();

		$_SERVER['REQUEST_URI'] = '/second';

		Diagnostics::persist();

		$this->assertSame( '/first', Diagnostics::last()['path'] ?? null, 'A second request within the throttle was written.' );

		Diagnostics::reset_throttle();
		Diagnostics::persist();

		$this->assertSame( '/second', Diagnostics::last()['path'] ?? null, 'The throttle did not let a later write through.' );
	}

	/**
	 * The report carries what the investigation needs, and nothing sensitive.
	 */
	public function test_the_report_carries_no_secrets(): void {
		$this->given_early(
			array(
				'evaluated'      => true,
				'mode'           => 'exception',
				'library'        => 'unscoped',
				'failure'        => 'RuntimeException: could not reach redis://firewall:s3cr3t-pass@10.0.0.9:6379',
				'failure_origin' => '/code/vendor/kanopi/firewall/src/Firewall.php:42',
				'autoloader'     => array(
					'source' => 'option',
					'file'   => '/code/web/wp-content/mu-plugins/vendor/autoload.php',
					'named'  => 'option',
				),
			)
		);

		$_SERVER['REQUEST_URI']    = '/learning-resources/page/?token=abc123secret&email=someone%40example.com';
		$_SERVER['REQUEST_METHOD'] = 'GET';
		$_SERVER['REMOTE_ADDR']    = '198.51.100.77';
		$_SERVER['HTTP_COOKIE']    = 'wordpress_logged_in_abc=cookie-value-xyz';

		Diagnostics::persist();

		$report = Diagnostics::last_anomaly();

		$this->assertIsArray( $report );
		$this->assertSame( 'fail-open', $report['anomaly'] );
		$this->assertSame( '/learning-resources/page/', $report['path'] );
		$this->assertSame( 'GET', $report['method'] );
		$this->assertSame( 'exception', $report['mode']['early'] );
		$this->assertSame( 'option', $report['early']['autoloader']['source'] );
		$this->assertSame( '/code/vendor/kanopi/firewall/src/Firewall.php:42', $report['early']['failure_origin'] );
		$this->assertSame( Plugin::instance()->paths()->compiled_file(), $report['compiled']['path'] );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{12}$/', (string) $report['compiled']['hash'] );
		$this->assertArrayHasKey( 'runner', $report['cache'] );
		$this->assertNotNull( $report['library']['version'] );

		$json = (string) wp_json_encode( $report );

		foreach ( array( 'abc123secret', 'someone', '198.51.100.77', 'cookie-value-xyz', 's3cr3t-pass' ) as $secret ) {
			$this->assertStringNotContainsString( $secret, $json, "The report carries {$secret}." );
		}
	}

	/**
	 * Which reports are anomalies.
	 */
	public function test_what_counts_as_an_anomaly(): void {
		$early = static fn ( array $early ): array => array(
			'early'  => $early + array(
				'called'    => true,
				'evaluated' => false,
			),
			'runner' => array(),
		);

		$this->assertNull( Diagnostics::anomaly( $early( array( 'evaluated' => true ) ) ) );
		$this->assertNull( Diagnostics::anomaly( $early( array( 'reason' => 'deferred-login' ) ) ), 'A deferred login is the design working.' );
		$this->assertNull( Diagnostics::anomaly( $early( array( 'reason' => 'switched-off' ) ) ) );
		$this->assertSame( 'not-evaluated', Diagnostics::anomaly( $early( array( 'reason' => 'no-autoloader' ) ) ) );
		$this->assertSame( 'not-evaluated', Diagnostics::anomaly( $early( array( 'reason' => 'library-missing' ) ) ) );
		$this->assertSame(
			'fail-open',
			Diagnostics::anomaly(
				$early(
					array(
						'evaluated' => true,
						'failure'   => 'RuntimeException: x',
					)
				)
			)
		);
		$this->assertSame(
			'fail-open',
			Diagnostics::anomaly(
				array(
					'early'  => array(),
					'runner' => array( 'failure' => 'could-not-start' ),
				)
			)
		);
		$this->assertSame(
			'early-verdict-deferred',
			Diagnostics::anomaly(
				array(
					'early'  => array(
						'called'    => true,
						'evaluated' => true,
					),
					'runner' => array( 'early_verdict' => 'challenge' ),
				)
			)
		);
		$this->assertNull(
			Diagnostics::anomaly(
				array(
					'early'  => array(
						'called'    => true,
						'evaluated' => true,
					),
					'runner' => array( 'early_verdict' => 'solved' ),
				)
			),
			'A solved challenge is handed on by design.'
		);
		$this->assertNull(
			Diagnostics::anomaly(
				array(
					'early'  => array( 'called' => false ),
					'runner' => array( 'evaluated' => true ),
				)
			),
			'A site with no snippet is not an anomaly.'
		);
	}

	/**
	 * Site Health raises a recent fail-open as critical, with what failed.
	 */
	public function test_site_health_reports_a_recent_fail_open(): void {
		$this->given_settings( array( 'global' => array( 'mode' => 'exception' ) ) );

		// This request itself was not evaluated by any snippet.
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		$this->given_anomaly(
			array(
				'anomaly' => 'fail-open',
				'mode'    => array(
					'runner'     => null,
					'early'      => 'exception',
					'configured' => 'exception',
				),
				'early'   => array(
					'called'         => true,
					'evaluated'      => true,
					'failure'        => 'RuntimeException: the evaluator broke',
					'failure_origin' => '/code/src/Thing.php:12',
				),
			)
		);

		$check = Site_Health::check( 'evaluation' );

		$this->assertSame( 'critical', $check['status'] );
		$this->assertSame( 'The firewall recently let a request through because it failed', $check['label'] );
		$this->assertStringContainsString( 'the evaluator broke', $check['description'] );
		$this->assertStringContainsString( '/code/src/Thing.php:12', $check['description'] );
		$this->assertStringContainsString( '/sample-page/', $check['description'] );
		$this->assertStringContainsString( 'early-report', $check['description'] );
	}

	/**
	 * A recent early path that did not evaluate is a recommendation, with the fix.
	 */
	public function test_site_health_reports_a_recent_not_evaluated_request(): void {
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		$this->given_anomaly(
			array(
				'anomaly' => 'not-evaluated',
				'early'   => array(
					'called'    => true,
					'evaluated' => false,
					'reason'    => 'no-autoloader',
				),
			)
		);

		$check = Site_Health::check( 'evaluation' );

		$this->assertSame( 'recommended', $check['status'] );
		$this->assertSame( 'The wp-config.php snippet recently did not evaluate a web request', $check['label'] );
		$this->assertStringContainsString( esc_html( Site_Health::early_reason_text( 'no-autoloader' ) ), $check['description'] );
		$this->assertStringContainsString( 'basic_firewall_evaluate(', $check['actions'], 'The fix -- the snippet -- is not offered.' );
	}

	/**
	 * An old anomaly is left to the CLI, not raised in Site Health.
	 */
	public function test_site_health_ignores_an_old_anomaly(): void {
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		$this->given_anomaly(
			array(
				'time'    => time() - Diagnostics::RECENT - 60,
				'anomaly' => 'not-evaluated',
				'early'   => array(
					'called'    => true,
					'evaluated' => false,
					'reason'    => 'no-autoloader',
				),
			)
		);

		$this->assertNotSame( 'The wp-config.php snippet recently did not evaluate a web request', Site_Health::check( 'evaluation' )['label'] );
	}

	/**
	 * The status command's one-line summary says what happened, and when.
	 */
	public function test_the_status_summary(): void {
		$this->assertSame( 'none recorded', Diagnostics::summary( null ) );

		$summary = Diagnostics::summary(
			array(
				'time'    => time() - 120,
				'method'  => 'GET',
				'path'    => '/learning-resources/',
				'anomaly' => 'fail-open',
				'early'   => array(
					'called'         => true,
					'evaluated'      => true,
					'failure'        => 'RuntimeException: broke',
					'failure_origin' => '/code/x.php:9',
				),
				'runner'  => array( 'evaluated' => false ),
			)
		);

		$this->assertStringStartsWith( 'FAIL-OPEN; ' . human_time_diff( time() - 120 ) . ' ago; GET /learning-resources/; early: evaluated', $summary );
		$this->assertStringContainsString( 'early failure: RuntimeException: broke at /code/x.php:9', $summary );

		$this->assertStringContainsString(
			'early: NOT evaluated (no-autoloader)',
			Diagnostics::summary(
				array(
					'time'   => time(),
					'early'  => array(
						'called'    => true,
						'evaluated' => false,
						'reason'    => 'no-autoloader',
					),
					'runner' => array(
						'evaluated' => true,
						'outcome'   => 'allowed',
					),
				)
			)
		);
	}

	/**
	 * The debug header's report is compact and carries both halves.
	 */
	public function test_the_compact_report(): void {
		$this->given_early(
			array(
				'evaluated'      => true,
				'failure'        => 'RuntimeException: secret message text',
				'failure_origin' => '/code/private/place/Thing.php:12',
			)
		);

		$compact = Diagnostics::compact();

		$this->assertSame( 'RuntimeException @ Thing.php:12', $compact['early']['failure'] );
		$this->assertArrayHasKey( 'runner', $compact );
		$this->assertStringNotContainsString( 'secret message text', (string) wp_json_encode( $compact ) );
		$this->assertStringNotContainsString( '/code/private/place', (string) wp_json_encode( $compact ) );
		$this->assertFalse( Diagnostics::debug_enabled() || defined( 'BASIC_FIREWALL_DEBUG' ), 'BASIC_FIREWALL_DEBUG is defined for the test site, so nothing here says it is off by default.' );
	}

	/**
	 * #34's object-cache hypothesis: the backend does not change an exception-mode verdict.
	 *
	 * With `cache.backend: object_cache` the compiler writes no pool -- YAML
	 * cannot carry an object -- and records where one goes; the runner hands
	 * the object cache over at those paths, and the wp-config.php path, which
	 * has no object cache, leaves the library on its file default. So the two
	 * paths build their firewalls differently on exactly the Pantheon setup
	 * the report came from. Both are built here the way each path builds
	 * them, with a persistent object cache in place, and both must reach the
	 * same verdicts as a verdict -- never a failure the paths would fail open
	 * on.
	 */
	public function test_the_object_cache_backend_does_not_change_an_exception_mode_verdict(): void {
		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$this->markTestSkipped( 'BASIC_FIREWALL_MODE pins this site\'s mode.' );
		}

		$external = wp_using_ext_object_cache();

		$this->given_settings(
			array(
				'global'    => array( 'mode' => 'exception' ),
				'challenge' => array(
					'provider' => 'math',
					'secret'   => str_repeat( 'diagnostics-secret-', 3 ),
				),
				'storage'   => array( 'backend' => 'file' ),
				'cache'     => array( 'backend' => 'object_cache' ),
				'rules'     => array(
					array(
						'id'       => 'diagnostics_crawlers',
						'type'     => 'user_agent',
						'label'    => 'Crawlers',
						'enabled'  => true,
						'response' => 'block',
						'weight'   => 0,
						'record'   => 'no',
						'settings' => array(
							'match_type'      => 'any',
							'cache_detection' => true,
							'bot_source'      => 'curated',
							'conditions'      => array(
								array(
									'variable' => 'bot',
									'operator' => 'equals',
									'value'    => 'true',
								),
							),
						),
					),
					array(
						'id'                 => 'diagnostics_altcha',
						'type'               => 'url',
						'label'              => 'Per-rule ALTCHA',
						'enabled'            => true,
						'response'           => 'challenge',
						'challenge_provider' => 'altcha',
						'weight'             => 0,
						'record'             => 'no',
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
					),
				),
			)
		);

		wp_using_ext_object_cache( true );

		try {
			$this->assertTrue( Plugin::instance()->compiled()->rebuild()['written'] );
			$this->assertNotSame( array(), Plugin::instance()->compiled()->cache_pool_paths(), 'The user agent rule\'s cache path was not recorded, so nothing here is handed over.' );

			$compiled = Plugin::instance()->paths()->compiled_file();
			$paths    = array(
				'early'  => array(),
				'runner' => \Kanopi\BasicFirewall\Cache\Cache_Backend::overrides(),
			);

			$this->assertNotSame( array(), $paths['runner'], 'The object cache was not handed over, so the runner path is not the one under test.' );

			$browser = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36';
			$crawler = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

			foreach ( $paths as $path => $overrides ) {
				$firewall = \Kanopi\Firewall\Firewall::create( array( $compiled ), $overrides );

				$this->assertSame( 'exception', $firewall->getMode()->value );
				$this->assertSame( 'challenge', $this->verdict( $firewall, '/learning-resources/page/', $browser ), "The {$path} path did not challenge." );
				$this->assertSame( 'blocked', $this->verdict( $firewall, '/', $crawler ), "The {$path} path did not refuse the crawler." );
				$this->assertSame( 'allowed', $this->verdict( $firewall, '/', $browser ), "The {$path} path refused an unmatched request." );
			}
		} finally {
			wp_using_ext_object_cache( $external );
		}
	}

	/**
	 * What a firewall makes of a request: a verdict kind, `allowed`, or the failure.
	 *
	 * @param \Kanopi\Firewall\Firewall $firewall   The firewall.
	 * @param string                    $path       Request path.
	 * @param string                    $user_agent User-Agent header.
	 */
	private function verdict( \Kanopi\Firewall\Firewall $firewall, string $path, string $user_agent ): string {
		$request = Request::create( $path, 'GET', array(), array(), array(), array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$request->headers->set( 'User-Agent', $user_agent );

		try {
			return $firewall->evaluate( $request ) ? 'allowed' : 'refused';
		} catch ( \Throwable $e ) {
			return \Kanopi\BasicFirewall\Runtime\Outcome_Responder::verdict_kind( $e ) ?? 'failure: ' . get_class( $e ) . ': ' . $e->getMessage();
		}
	}

	/**
	 * Exception mode with one challenge rule, compiled.
	 */
	private function given_exception_mode(): void {
		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$this->markTestSkipped( 'BASIC_FIREWALL_MODE pins this site\'s mode.' );
		}

		$this->given_settings(
			array(
				'global'    => array( 'mode' => 'exception' ),
				'challenge' => array(
					'provider' => 'math',
					'secret'   => str_repeat( 'diagnostics-secret-', 3 ),
				),
				'storage'   => array( 'backend' => 'file' ),
				'rules'     => array(
					array(
						'id'       => 'diagnostics_challenge',
						'type'     => 'url',
						'label'    => 'Diagnostics challenge',
						'enabled'  => true,
						'response' => 'challenge',
						'weight'   => 0,
						'record'   => 'no',
						'settings' => array(
							'match_type' => 'any',
							'conditions' => array(
								array(
									'variable' => 'path',
									'operator' => 'equals',
									'value'    => '/bfw-diagnostics-match',
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
	 * Call the runner's evaluation directly, past the wp-config.php guard.
	 *
	 * @param string  $compiled The compiled file.
	 * @param Request $request  The request.
	 */
	private function evaluate_compiled( string $compiled, Request $request ): bool {
		$method = new \ReflectionMethod( Runner::class, 'evaluate_compiled' );
		$method->setAccessible( true );

		return (bool) $method->invoke( new Runner(), $compiled, $request );
	}

	/**
	 * Set the bootstrap's report for this request.
	 *
	 * @param array<string, mixed> $early Fields over a called, unevaluated report.
	 */
	private function given_early( array $early ): void {
		$GLOBALS['basic_firewall_early'] = $early + array(
			'called'      => true,
			'credentials' => true,
			'evaluated'   => false,
			'reason'      => null,
			'responder'   => true,
		);
	}

	/**
	 * Save an anomaly report as the runner would have.
	 *
	 * @param array<string, mixed> $report Fields over a plausible report.
	 */
	private function given_anomaly( array $report ): void {
		set_transient(
			Diagnostics::ANOMALY,
			$report + array(
				'time'   => time() - 60,
				'method' => 'GET',
				'path'   => '/sample-page/',
				'runner' => array( 'evaluated' => false ),
				'mode'   => array(
					'configured' => 'block',
					'early'      => 'block',
					'runner'     => null,
				),
			),
			Diagnostics::TTL
		);
	}

	/**
	 * What was written to the error log.
	 */
	private function logged(): string {
		return (string) file_get_contents( $this->log ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the captured log.
	}
}
