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
	 * A failure the early path fails open on is logged every time, with its origin.
	 */
	public function test_a_fail_open_is_logged_every_time(): void {
		$options = basic_firewall_options( array( 'private_path' => $this->private ) );

		$GLOBALS['basic_firewall_early'] = array(
			'called'    => true,
			'evaluated' => true,
		);

		$this->assertTrue( basic_firewall_answer_outcome( new \LogicException( 'broke once' ), null, $options ) );
		$this->assertTrue( basic_firewall_answer_outcome( new \LogicException( 'broke twice' ), null, $options ) );

		$logged = $this->logged();

		$this->assertSame( 2, substr_count( $logged, 'Basic Firewall [warning]: fail-open (early): the firewall threw LogicException' ) );
		$this->assertStringContainsString( '"broke twice" at ' . __FILE__ . ':', $logged );
		$this->assertStringContainsString( 'EarlyDiagnosticsTest.php:', (string) $GLOBALS['basic_firewall_early']['failure_origin'] );
		$this->assertSame( 'LogicException: broke twice', $GLOBALS['basic_firewall_early']['failure'] );
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
	 * What was logged.
	 */
	private function logged(): string {
		return is_readable( $this->log ) ? (string) file_get_contents( $this->log ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- the captured log.
	}
}
