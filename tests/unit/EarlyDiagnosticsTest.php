<?php
/**
 * Tests for the bootstrap's own diagnostics: fail-open and not-evaluated logging.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\unit;

use PHPUnit\Framework\TestCase;

/**
 * What the wp-config.php path writes to the PHP error log, and how often.
 *
 * #34: a firewall that failed open on visitors' requests left nothing in the
 * log, and every status screen read the report of its own request.
 *
 * @coversNothing
 */
final class EarlyDiagnosticsTest extends TestCase {

	/**
	 * A private directory for the marker files.
	 *
	 * @var string
	 */
	private string $private = '';

	/**
	 * The captured error log.
	 *
	 * @var string
	 */
	private string $log = '';

	/**
	 * The error log setting as it was.
	 *
	 * @var string
	 */
	private string $previous = '';

	/**
	 * Load the bootstrap, and point the error log at a file.
	 */
	protected function setUp(): void {
		parent::setUp();

		require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

		$this->private = sys_get_temp_dir() . '/bfw-early-diagnostics-' . bin2hex( random_bytes( 4 ) );
		mkdir( $this->private, 0700 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a test's own scratch directory.

		$this->log      = $this->private . '/php-error.log';
		$this->previous = (string) ini_get( 'error_log' );

		ini_set( 'error_log', $this->log ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- captured for assertions, and put back.
	}

	/**
	 * Put the log back and remove the scratch directory.
	 */
	protected function tearDown(): void {
		ini_set( 'error_log', $this->previous ); // phpcs:ignore WordPress.PHP.IniSet.Risky -- put back.

		foreach ( (array) glob( $this->private . '/{,.}*', GLOB_BRACE ) as $file ) {
			if ( is_string( $file ) && is_file( $file ) ) {
				unlink( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a test's own scratch files.
			}
		}

		rmdir( $this->private ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- as above.

		unset( $GLOBALS['basic_firewall_early'] );

		parent::tearDown();
	}

	/**
	 * A throwable is described by class, masked message and origin -- not a trace.
	 */
	public function test_a_throwable_is_described_without_secrets(): void {
		$e    = new \RuntimeException( "could not connect to\nredis://firewall:s3cr3t@10.0.0.9:6379/0" );
		$line = __LINE__ - 1;

		$described = basic_firewall_describe_throwable( $e );

		$this->assertSame( 'RuntimeException', $described['class'] );
		$this->assertSame( 'could not connect to redis://firewall:***@10.0.0.9:6379/0', $described['message'] );
		$this->assertSame( __FILE__ . ':' . $line, $described['origin'] );

		$long = basic_firewall_describe_throwable( new \RuntimeException( str_repeat( 'x', 500 ) ) );

		$this->assertSame( 303, strlen( $long['message'] ), 'A long message was not cut short.' );
	}

	/**
	 * A reason that means the snippet is doing nothing is logged, once per interval.
	 */
	public function test_a_not_evaluated_reason_is_logged_once_per_interval(): void {
		$options = basic_firewall_options( array( 'private_path' => $this->private ) );

		$GLOBALS['basic_firewall_early'] = array( 'called' => true );

		$this->assertTrue( basic_firewall_not_evaluated( 'no-compiled-file', $options ) );
		$this->assertTrue( basic_firewall_not_evaluated( 'no-compiled-file', $options ) );

		$this->assertSame( 'no-compiled-file', $GLOBALS['basic_firewall_early']['reason'] );
		$this->assertSame( 1, substr_count( $this->logged(), 'Basic Firewall [warning]: not-evaluated (early)' ), 'Two requests logged the same reason twice.' );
		$this->assertStringContainsString( '(no-compiled-file)', $this->logged() );
		$this->assertStringContainsString( 'once every 15 minutes', $this->logged() );

		// Another reason is its own warning.
		basic_firewall_not_evaluated( 'multisite', $options );

		$this->assertSame( 2, substr_count( $this->logged(), 'not-evaluated (early)' ) );

		// And with no interval, every time.
		basic_firewall_not_evaluated( 'no-compiled-file', array( 'warn_interval' => 0 ) + $options );

		$this->assertSame( 3, substr_count( $this->logged(), 'not-evaluated (early)' ) );
	}

	/**
	 * The configuration working as meant is not a warning.
	 */
	public function test_benign_reasons_are_not_logged(): void {
		$options = basic_firewall_options( array( 'private_path' => $this->private ) );

		foreach ( basic_firewall_benign_reasons() as $reason ) {
			basic_firewall_not_evaluated( $reason, $options );
		}

		$this->assertSame( '', $this->logged() );
		$this->assertSame( array( 'disabled', 'switched-off', 'deferred-login' ), basic_firewall_benign_reasons() );
	}

	/**
	 * A fail-open is logged at once, then at most once a minute, with a count (#41).
	 */
	public function test_a_fail_open_is_logged_once_a_minute_with_a_count(): void {
		$options = basic_firewall_options( array( 'private_path' => $this->private ) );

		$GLOBALS['basic_firewall_early'] = array(
			'called'    => true,
			'evaluated' => true,
		);

		// Thrown from one place, as a persistent failure is.
		$broke = static fn ( string $message ): \LogicException => new \LogicException( $message );

		$this->assertTrue( basic_firewall_answer_outcome( $broke( 'broke once' ), null, $options ) );
		$this->assertTrue( basic_firewall_answer_outcome( $broke( 'broke twice' ), null, $options ), 'A held-back line refused the request.' );
		$this->assertTrue( basic_firewall_answer_outcome( $broke( 'broke thrice' ), null, $options ) );

		$logged = $this->logged();

		$this->assertSame( 1, substr_count( $logged, 'Basic Firewall [warning]: fail-open (early): the firewall threw LogicException' ), 'Three requests within a minute logged more than one line.' );
		$this->assertStringContainsString( '"broke once" at ' . __FILE__ . ':', $logged, 'The first occurrence was not the one logged.' );
		$this->assertSame( 'LogicException: broke thrice', $GLOBALS['basic_firewall_early']['failure'], 'A held-back line was not still recorded in the report.' );

		$markers = (array) glob( $this->private . '/.warned-fail-open-*' );

		$this->assertCount( 1, $markers, 'The interval is not remembered anywhere another process can see.' );

		$state = json_decode( (string) file_get_contents( (string) $markers[0] ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the bootstrap's marker.

		$this->assertSame( 2, $state['suppressed'] ?? null );

		// A minute on, the next is logged, with how many were held back.
		$aged = array(
			'logged'     => time() - 61,
			'suppressed' => 2,
		);
		$aged = (string) json_encode( $aged ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress in the unit suite.

		file_put_contents( (string) $markers[0], $aged ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- ageing the bootstrap's marker.

		basic_firewall_answer_outcome( $broke( 'broke again' ), null, $options );

		$lines = array_values( array_filter( explode( "\n", $this->logged() ), static fn ( string $line ): bool => str_contains( $line, 'fail-open (early)' ) ) );

		$this->assertCount( 2, $lines );
		$this->assertStringContainsString( '"broke again"', $lines[1] );
		$this->assertMatchesRegularExpression( '/\(2 more since \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC\)$/', $lines[1], 'The line does not say how many were held back.' );

		// Another exception, or the same one from elsewhere, is its own line.
		basic_firewall_answer_outcome( new \RuntimeException( 'something else' ), null, $options );

		$this->assertSame( 3, substr_count( $this->logged(), 'fail-open (early)' ) );

		// And with no interval, every time.
		basic_firewall_answer_outcome( $broke( 'unthrottled' ), null, array( 'fail_open_interval' => 0 ) + $options );

		$this->assertSame( 4, substr_count( $this->logged(), 'fail-open (early)' ) );
	}

	/**
	 * The debug report carries no paths beyond a file name, and no message text.
	 */
	public function test_the_debug_report_is_compact(): void {
		$GLOBALS['basic_firewall_early'] = array(
			'called'         => true,
			'evaluated'      => true,
			'failure'        => 'LogicException: something private',
			'failure_origin' => '/srv/site/private/Thing.php:9',
			'autoloader'     => array(
				'source' => 'option',
				'file'   => '/srv/site/vendor/autoload.php',
			),
		);

		$report = basic_firewall_debug_report();
		$json   = (string) json_encode( $report ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress in the unit suite.

		$this->assertSame( 'LogicException @ Thing.php:9', $report['failure'] );
		$this->assertSame( 'option', $report['autoloader'] );
		$this->assertStringNotContainsString( '/srv/site', $json );
		$this->assertStringNotContainsString( 'something private', $json );
		$this->assertFalse( basic_firewall_debug_enabled(), 'BASIC_FIREWALL_DEBUG is on by default.' );
	}

	/**
	 * Rules the firewall could not construct are named, without their messages (#41).
	 */
	public function test_failed_rules_are_named_without_messages(): void {
		$firewall = new class() {
			/**
			 * What the library answers.
			 *
			 * @return list<array{bucket: string, plugin: string, error: string}>
			 */
			public function getFailedRules(): array { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- the library's method name.
				return array(
					array(
						'bucket' => 'block',
						'plugin' => 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Plugins\\Reputation:0',
						'error'  => 'could not reach https://user:secret@reputation.internal',
					),
					array(
						'bucket' => 'challenge',
						'plugin' => 'RateLimit:2',
						'error'  => 'no storage',
					),
				);
			}
		};

		$this->assertSame( array( 'block/Reputation:0', 'challenge/RateLimit:2' ), basic_firewall_failed_rules( $firewall ) );

		// A library copy too old to say, and one whose answer throws, cannot say.
		$this->assertNull( basic_firewall_failed_rules( new \stdClass() ) );
		$this->assertNull(
			basic_firewall_failed_rules(
				new class() {
					/**
					 * Fail the way a constructor throwing an Error would.
					 *
					 * @throws \TypeError Always.
					 */
					public function getFailedRules(): array { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- the library's method name. // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- the library's method name.
						throw new \TypeError( 'metadata must be of type array' );
					}
				}
			)
		);

		// The debug report carries the names, and never a message.
		$GLOBALS['basic_firewall_early'] = array(
			'called'       => true,
			'evaluated'    => true,
			'failed_rules' => basic_firewall_failed_rules( $firewall ),
		);

		$report = basic_firewall_debug_report();

		$this->assertSame( array( 'block/Reputation:0', 'challenge/RateLimit:2' ), $report['failed_rules'] );
		$this->assertStringNotContainsString( 'secret', (string) json_encode( $report ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- no WordPress in the unit suite.

		// Null, not an empty list, when this path built no firewall.
		$GLOBALS['basic_firewall_early'] = array( 'called' => true );

		$this->assertNull( basic_firewall_debug_report()['failed_rules'] );
	}

	/**
	 * The early path samples failed rules, rather than asking on every request (#41).
	 *
	 * Asking builds every rule, undoing the library's lazy construction, so
	 * an ordinary request with no sample due must never ask.
	 */
	public function test_failed_rules_are_sampled_on_the_early_path(): void {
		$options  = basic_firewall_options( array( 'private_path' => $this->private ) );
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

				return array(
					array(
						'bucket' => 'block',
						'plugin' => 'Url:0',
						'error'  => 'broken',
					),
				);
			}
		};

		// The throttle lets the first request through.
		$GLOBALS['basic_firewall_early'] = array( 'called' => true );

		$this->assertTrue( basic_firewall_sample_failed_rules( $firewall, $options ) );
		$this->assertSame( array( 'block/Url:0' ), $GLOBALS['basic_firewall_early']['failed_rules'] );
		$this->assertSame( 'interval', $GLOBALS['basic_firewall_early']['failed_rules_sampled'] );
		$this->assertFileExists( $this->private . '/.sampled-failed-rules-early' );

		// Ordinary requests within the interval never ask.
		for ( $i = 0; $i < 5; $i++ ) {
			$GLOBALS['basic_firewall_early'] = array( 'called' => true );

			$this->assertFalse( basic_firewall_sample_failed_rules( $firewall, $options ) );
			$this->assertNull( $GLOBALS['basic_firewall_early']['failed_rules'] );
			$this->assertNull( $GLOBALS['basic_firewall_early']['failed_rules_sampled'] );
		}

		$this->assertSame( 1, $firewall->asked, 'An ordinary request built every rule to ask.' );
		$this->assertNull( basic_firewall_debug_report()['failed_rules'] );

		// Debug and a failure ask regardless -- once per request.
		$this->assertTrue( basic_firewall_sample_failed_rules( $firewall, $options, 'failure' ) );
		$this->assertFalse( basic_firewall_sample_failed_rules( $firewall, $options, 'failure' ), 'One request asked twice.' );
		$this->assertSame( 'failure', basic_firewall_debug_report()['failed_rules_sampled'] );

		$GLOBALS['basic_firewall_early'] = array( 'called' => true );

		$this->assertTrue( basic_firewall_sample_failed_rules( $firewall, $options, 'debug' ) );
		$this->assertSame( 3, $firewall->asked );

		// Once the interval has passed, the next ordinary request asks.
		touch( $this->private . '/.sampled-failed-rules-early', time() - 61 ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- ageing the marker.
		clearstatcache();

		$GLOBALS['basic_firewall_early'] = array( 'called' => true );

		$this->assertTrue( basic_firewall_sample_failed_rules( $firewall, $options ) );
		$this->assertSame( 4, $firewall->asked );
	}

	/**
	 * What was logged.
	 */
	private function logged(): string {
		return is_readable( $this->log ) ? (string) file_get_contents( $this->log ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the captured log.
	}
}
