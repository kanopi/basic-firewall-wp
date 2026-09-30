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
			'sample'    => get_transient( Diagnostics::SAMPLE ),
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
			Diagnostics::SAMPLE  => 'sample',
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
	 * The same runner fail-open is logged at most once a minute, with a count (#41).
	 */
	public function test_a_runner_fail_open_is_logged_once_a_minute(): void {
		$this->given_exception_mode();

		// One class, cloned per request, so each failure has one origin.
		$broken = new class() extends Request {
			/**
			 * Fail the same way, from the same place, every time.
			 *
			 * @throws \LogicException Always.
			 */
			public function getPathInfo(): string {
				throw new \LogicException( 'the runner keeps breaking' );
			}
		};

		for ( $i = 0; $i < 3; $i++ ) {
			Runner::reset();

			$this->assertTrue( $this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), clone $broken ), 'A held-back line refused the request.' );
			$this->assertSame( 'evaluation-failed', Runner::state()['failure'], 'A held-back line was not still recorded for the report.' );
		}

		$this->assertSame( 1, substr_count( $this->logged(), 'fail-open (runner)' ), 'Three failures within a minute logged more than one line.' );

		$markers = (array) glob( Plugin::instance()->paths()->base() . '/.warned-fail-open-*' );

		$this->assertCount( 1, $markers );
		$this->assertSame( 2, json_decode( (string) file_get_contents( (string) $markers[0] ), true )['suppressed'] ?? null ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the marker.

		// A minute on, logged again, saying how many were held back.
		$aged = (string) wp_json_encode(
			array(
				'logged'     => time() - 61,
				'suppressed' => 2,
			)
		);

		file_put_contents( (string) $markers[0], $aged ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- ageing the marker.

		Runner::reset();
		$this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), clone $broken );

		$this->assertSame( 2, substr_count( $this->logged(), 'fail-open (runner)' ) );
		$this->assertMatchesRegularExpression( '/fail-open \(runner\).*\(2 more since \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\)/', $this->logged() );

		// The early path's marker for the same failure is its own.
		$this->assertSame( Diagnostics::fail_open_marker( 'runner|LogicException|x' ), Diagnostics::fail_open_marker( 'runner|LogicException|x' ) );
		$this->assertNotSame( Diagnostics::fail_open_marker( 'early|LogicException|x' ), Diagnostics::fail_open_marker( 'runner|LogicException|x' ) );
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
	 * A rule the runner's firewall could not construct is recorded, and is an anomaly (#41).
	 */
	public function test_failed_rules_on_the_runner_path_are_recorded(): void {
		$this->given_exception_mode();

		// Rule 0 turned into a reputation rule with no provider: its
		// constructor throws, and the library skips it.
		$break = static fn ( array $overrides ): array => array( '[plugins][0][plugin]' => 'Kanopi\\Firewall\\Plugins\\Reputation' ) + $overrides;

		add_filter( 'basic_firewall_config_overrides', $break );

		try {
			$this->assertTrue( $this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), Request::create( '/bfw-diagnostics-match' ) ) );
		} finally {
			remove_filter( 'basic_firewall_config_overrides', $break );
		}

		$this->assertSame( array( 'challenge/Reputation:0' ), Runner::state()['failed_rules'] );
		$this->assertSame( array( 'challenge/Reputation:0' ), Diagnostics::compact()['runner']['failed_rules'], 'The debug header does not name the rule.' );

		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		Diagnostics::persist();

		$report = Diagnostics::last_anomaly();

		$this->assertIsArray( $report, 'A request that ran without a rule was not kept as an anomaly.' );
		$this->assertSame( 'failed-rules', $report['anomaly'] );
		$this->assertSame( array( 'failed-rules' ), $report['anomalies'] );
		$this->assertSame( array( 'challenge/Reputation:0' ), $report['runner']['failed_rules'] );
		$this->assertNull( $report['early']['failed_rules'], 'An early path that built no firewall reported an empty list.' );
		$this->assertStringNotContainsString( 'upstream', (string) wp_json_encode( $report ), 'The constructor\'s message reached the report.' );
		$this->assertStringContainsString( 'runner failed rules: 1 (challenge/Reputation:0; sampled: interval)', Diagnostics::summary( $report ) );
		$this->assertSame( 'interval', $report['runner']['failed_rules_sampled'] );

		// The sample is kept on its own, for status and early-report.
		$sample = Diagnostics::last_sample();

		$this->assertSame( array( 'challenge/Reputation:0' ), $sample['runner']['failed_rules'] ?? null );
		$this->assertStringContainsString( 'runner: 1 failed: challenge/Reputation:0', Diagnostics::sample_summary( $sample ) );

		// The next request, within the interval, is not sampled: null, not "none failed".
		Runner::reset();

		$this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), Request::create( '/nothing-matches-this' ) );

		$this->assertNull( Runner::state()['failed_rules'], 'A request within the interval built every rule to ask.' );
		$this->assertNull( Runner::state()['failed_rules_sampled'] );

		// Once it is due, a healthy firewall records an empty list, which is not an anomaly.
		Diagnostics::reset_throttle();
		Runner::reset();

		$this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), Request::create( '/nothing-matches-this' ) );

		$this->assertSame( array(), Runner::state()['failed_rules'] );
		$this->assertSame( 'interval', Runner::state()['failed_rules_sampled'] );
	}

	/**
	 * Failed rules are sampled, not asked on every request (#41).
	 *
	 * Asking builds every rule, which undoes the library's lazy construction:
	 * a visitor an early rule settled would pay for the whole ruleset.
	 */
	public function test_failed_rules_are_sampled_not_asked_every_request(): void {
		$firewall = new class() {
			/**
			 * How many times the library was asked.
			 *
			 * @var int
			 */
			public int $asked = 0;

			/**
			 * Count the question.
			 *
			 * @return list<array{bucket: string, plugin: string, error: string}>
			 */
			public function getFailedRules(): array { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- the library's method name.
				++$this->asked;

				return array();
			}
		};

		// The throttle lets the first one through.
		$this->assertSame( 'interval', Diagnostics::sample_failed_rules( $firewall, null )['sampled'] );
		$this->assertSame( 1, $firewall->asked );

		// An ordinary request within the interval never asks.
		for ( $i = 0; $i < 5; $i++ ) {
			$this->assertSame(
				array(
					'failed_rules' => null,
					'sampled'      => null,
				),
				Diagnostics::sample_failed_rules( $firewall, null )
			);
		}

		$this->assertSame( 1, $firewall->asked, 'An ordinary request built every rule to ask.' );

		// BASIC_FIREWALL_DEBUG and a failure ask regardless.
		$this->assertSame( 'debug', Diagnostics::sample_failed_rules( $firewall, 'debug' )['sampled'] );
		$this->assertSame( 'failure', Diagnostics::sample_failed_rules( $firewall, 'failure' )['sampled'] );
		$this->assertSame( 3, $firewall->asked );

		// And once the interval has passed, the next ordinary request asks.
		touch( Plugin::instance()->paths()->base() . '/.sampled-failed-rules-runner', time() - Diagnostics::SAMPLE_INTERVAL - 1 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- ageing the marker.
		clearstatcache();

		$this->assertSame( 'interval', Diagnostics::sample_failed_rules( $firewall, null )['sampled'] );
		$this->assertSame( 4, $firewall->asked );
	}

	/**
	 * A runner fail-open samples failed rules even when no sample is due (#41).
	 */
	public function test_a_runner_fail_open_samples_failed_rules(): void {
		$this->given_exception_mode();

		// Not due.
		touch( Plugin::instance()->paths()->base() . '/.sampled-failed-rules-runner' ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- the marker, as a recent sample leaves it.
		clearstatcache();

		$request = new class() extends Request {
			/**
			 * Fail partway through evaluating.
			 *
			 * @throws \LogicException Always.
			 */
			public function getPathInfo(): string {
				throw new \LogicException( 'broke while sampling was not due' );
			}
		};

		$this->assertTrue( $this->evaluate_compiled( Plugin::instance()->paths()->compiled_file(), $request ) );
		$this->assertSame( 'failure', Runner::state()['failed_rules_sampled'] );
		$this->assertSame( array(), Runner::state()['failed_rules'] );
	}

	/**
	 * Site Health raises recent failed rules, critical where the mode refuses (#41).
	 */
	public function test_site_health_reports_recent_failed_rules(): void {
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		$this->given_anomaly(
			array(
				'anomaly'   => 'failed-rules',
				'anomalies' => array( 'failed-rules' ),
				'early'     => array(
					'called'       => true,
					'evaluated'    => true,
					'failed_rules' => array( 'block/Reputation:0' ),
				),
			)
		);

		$check = Site_Health::check( 'evaluation' );

		$this->assertSame( 'critical', $check['status'], 'A block-mode firewall running without a rule is not critical.' );
		$this->assertSame( 'The firewall recently ran without some of its rules', $check['label'] );
		$this->assertStringContainsString( 'block/Reputation:0', $check['description'] );
		$this->assertStringContainsString( 'wp-config.php path', $check['description'] );

		// In log mode nothing is refused either way, so it is a recommendation.
		$this->given_anomaly(
			array(
				'anomaly' => 'failed-rules',
				'mode'    => array(
					'configured' => 'log',
					'early'      => 'log',
					'runner'     => null,
				),
				'runner'  => array(
					'evaluated'    => true,
					'failed_rules' => array( 'block/Reputation:0' ),
				),
			)
		);

		$this->assertSame( 'recommended', Site_Health::check( 'evaluation' )['status'] );
	}

	/**
	 * A path running another mode from the one compiled is a mismatch; an override is not (#41).
	 */
	public function test_a_mode_mismatch_is_flagged_and_overrides_are_reported(): void {
		$report = static fn ( array $mode, array $early = array(), array $runner = array() ): array => array(
			'mode'     => $mode + array(
				'configured' => 'block',
				'compiled'   => 'block',
				'early'      => null,
				'runner'     => null,
			),
			'early'    => $early,
			'runner'   => $runner,
			'compiled' => array(),
		);

		$this->assertSame( array(), Diagnostics::compare( $report( array( 'early' => 'block' ) ) )['mismatch'] );

		$this->assertSame(
			array( 'mode (early): ran log, configured block' ),
			Diagnostics::compare( $report( array( 'early' => 'log' ) ) )['mismatch'],
			'A web request running log mode on a block-mode site was not flagged.'
		);

		// The compile's mode is what is expected, advanced YAML included.
		$this->assertSame( array(), Diagnostics::compare( $report( array( 'compiled' => 'log', 'early' => 'log' ) ) )['mismatch'] ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- one line per case.

		// A panic file changes the mode, and says so: an override.
		$panicked = Diagnostics::compare( $report( array( 'runner' => 'log' ), array(), array( 'panic' => true ) ) );

		$this->assertSame( array(), $panicked['mismatch'], 'A panic file was flagged as a mismatch.' );
		$this->assertSame( array( 'runner: panic file (log)' ), $panicked['overrides'] );

		// Lockdown is run as block with lockdown on.
		$locked = Diagnostics::compare( $report( array( 'compiled' => 'lockdown', 'early' => 'block' ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- as above.

		$this->assertSame( array(), $locked['mismatch'] );
		$this->assertSame( array( 'early: lockdown (runs as block)' ), $locked['overrides'] );

		// And it is an anomaly of its own.
		$this->assertSame( 'mismatch', Diagnostics::anomaly( array( 'mismatch' => array( 'mode (early): ran log, configured block' ) ) ) );
	}

	/**
	 * A compiled file that differs between the paths or from the last compile is a mismatch (#41).
	 */
	public function test_a_stale_compiled_file_is_flagged(): void {
		$old     = time() - 3600;
		$report  = static fn ( array $compiled ): array => array(
			'mode'     => array(),
			'compiled' => $compiled + array(
				'path'  => '/private/firewall.yml',
				'mtime' => time() - 3600,
				'hash'  => 'aaaaaaaaaaaa',
				'early' => null,
				'meta'  => array(
					'hash'        => 'aaaaaaaaaaaa',
					'compiled_at' => time() - 3600,
				),
			),
		);
		$early   = static fn ( array $early ): array => $early + array(
			'path'  => '/private/firewall.yml',
			'mtime' => time() - 3600,
			'hash'  => 'aaaaaaaaaaaa',
		);
		$compare = static fn ( array $compiled ): array => Diagnostics::compare( $report( $compiled ) )['mismatch'];

		$this->assertSame( array(), $compare( array( 'early' => $early( array() ) ) ), 'Matching files were flagged.' );

		$this->assertSame(
			array( 'compiled hash: this container\'s file is bbbbbbbbbbbb, the last compile wrote aaaaaaaaaaaa' ),
			$compare( array( 'hash' => 'bbbbbbbbbbbb', 'early' => $early( array( 'hash' => 'bbbbbbbbbbbb' ) ) ) ), // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- one line per case.
			'A container reading a stale copy was not flagged.'
		);

		$this->assertStringStartsWith( 'compiled hash: the early path saw cccccccccccc', $compare( array( 'early' => $early( array( 'hash' => 'cccccccccccc' ) ) ) )[0] ?? '' );
		$this->assertStringStartsWith( 'compiled file: the early path read /elsewhere/firewall.yml', $compare( array( 'early' => $early( array( 'path' => '/elsewhere/firewall.yml' ) ) ) )[0] ?? '' );

		// A bootstrap from before the hash: the mtime is compared instead.
		$this->assertStringStartsWith( 'compiled mtime:', $compare( array( 'early' => $early( array( 'hash' => null, 'mtime' => $old - 60 ) ) ) )[0] ?? '' ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- as above.

		// A compile from before the hash was recorded is not compared with.
		$this->assertSame( array(), $compare( array( 'hash' => 'bbbbbbbbbbbb', 'meta' => array( 'compiled_at' => $old ) ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- as above.

		// Nor is anything within SETTLE seconds of a compile, which a request can straddle.
		$this->assertSame(
			array(),
			$compare(
				array(
					'hash' => 'bbbbbbbbbbbb',
					'meta' => array(
						'hash'        => 'aaaaaaaaaaaa',
						'compiled_at' => time() - 5,
					),
				)
			)
		);
	}

	/**
	 * A compile records what it wrote, and a stale file is kept in the anomaly slot (#41).
	 */
	public function test_a_mismatch_survives_ordinary_requests(): void {
		$this->given_exception_mode();

		$meta = Plugin::instance()->compiled()->meta();
		$file = Plugin::instance()->paths()->compiled_file();

		$this->assertSame( substr( (string) hash_file( 'sha256', $file ), 0, 12 ), $meta['hash'] ?? null, 'The compile did not record the hash of what it wrote.' );
		$this->assertSame( 'exception', $meta['mode'] ?? null, 'The compile did not record the mode it wrote.' );

		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		// The last compile wrote something other than what this container
		// reads, an hour ago: well outside the window a request can straddle.
		update_option(
			\Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache::META_OPTION,
			array(
				'hash'        => 'ffffffffffff',
				'compiled_at' => time() - 3600,
			) + $meta,
			false
		);
		touch( $file, time() - 3600 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- ageing the compiled file, put back below.
		clearstatcache();

		try {
			Diagnostics::persist();
		} finally {
			update_option( \Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache::META_OPTION, $meta, false );
			touch( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- put back.
			clearstatcache();
		}

		$anomaly = Diagnostics::last_anomaly();

		$this->assertIsArray( $anomaly, 'A stale compiled file was not kept as an anomaly.' );
		$this->assertSame( 'mismatch', $anomaly['anomaly'] );
		$this->assertStringContainsString( 'the last compile wrote ffffffffffff', (string) ( $anomaly['mismatch'][0] ?? '' ) );
		$this->assertSame( 'ffffffffffff', $anomaly['compiled']['meta']['hash'] );
		$this->assertStringContainsString( 'mismatch: compiled hash', Diagnostics::summary( $anomaly ) );

		// An ordinary request afterwards does not overwrite it.
		Diagnostics::reset_throttle();
		Diagnostics::persist();

		$this->assertSame( array(), Diagnostics::last()['mismatch'] ?? null );
		$this->assertSame( 'mismatch', Diagnostics::last_anomaly()['anomaly'] ?? null, 'An ordinary request overwrote the mismatch.' );
	}

	/**
	 * Site Health raises a recent mismatch as a recommendation, with the rebuild (#41).
	 */
	public function test_site_health_reports_a_recent_mismatch(): void {
		$GLOBALS['basic_firewall_early'] = array( 'called' => false );

		$this->given_anomaly(
			array(
				'anomaly'  => 'mismatch',
				'mismatch' => array( 'compiled hash: this container\'s file is bbbbbbbbbbbb, the last compile wrote aaaaaaaaaaaa' ),
				'early'    => array(
					'called'    => true,
					'evaluated' => true,
				),
			)
		);

		$check = Site_Health::check( 'evaluation' );

		$this->assertSame( 'recommended', $check['status'] );
		$this->assertSame( 'A recent web request saw a different firewall configuration from the one last compiled', $check['label'] );
		$this->assertStringContainsString( 'the last compile wrote aaaaaaaaaaaa', $check['description'] );
		$this->assertNotSame( '', $check['actions'], 'The rebuild is not offered.' );
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
		$this->assertNull( Diagnostics::anomaly( $early( array( 'evaluated' => true, 'failed_rules' => array() ) ) ), 'Every rule built is not an anomaly.' ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- one line per case.
		$this->assertSame( 'failed-rules', Diagnostics::anomaly( $early( array( 'evaluated' => true, 'failed_rules' => array( 'block/Url:0' ) ) ) ) ); // phpcs:ignore WordPress.Arrays.ArrayDeclarationSpacing.AssociativeArrayFound -- as above.

		// Both problems are kept, the more serious first.
		$this->assertSame(
			array( 'fail-open', 'failed-rules' ),
			Diagnostics::anomalies(
				array(
					'early'  => array(),
					'runner' => array(
						'failure'      => 'evaluation-failed',
						'failed_rules' => array( 'block/Url:0' ),
					),
				)
			)
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
