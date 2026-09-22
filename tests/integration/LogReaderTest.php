<?php
/**
 * Reading the firewall log back.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Logging\Log_Reader;
use PHPUnit\Framework\TestCase;

/**
 * The log screen's questions, asked of the reader.
 *
 * The library gives this table dedicated columns for everything worth asking
 * about — who, what they asked for, which rule answered, on what agent. The
 * reader used to map three of them out of the JSON blob beside them and read
 * the timestamp from `created_at`, a column that does not exist, so the When
 * column was empty for every row ever written.
 *
 * @covers \Kanopi\BasicFirewall\Logging\Log_Reader
 */
final class LogReaderTest extends TestCase {

	/**
	 * A marker on every fixture row, so the cleanup cannot take anything else.
	 */
	private const MARKER = 'log-reader-test-fixture';

	/**
	 * Write the rows this class reads back.
	 *
	 * Written rather than assumed. The first version of this skipped unless the
	 * site happened to have logged something, which made it a coincidence
	 * rather than a test -- and it skipped in every CI run, because the
	 * lifecycle tests drop this table on their way past and nothing recreates
	 * it.
	 *
	 * The rows go in through the library's own handler, so the table is created
	 * with the library's schema and the reader is tested against what actually
	 * gets written rather than against a fixture somebody hand-shaped.
	 */
	protected function setUp(): void {
		parent::setUp();

		$reader = new Log_Reader();
		$table  = $reader->table();

		if ( null === $table ) {
			$this->markTestSkipped( 'This site has no database log handler configured.' );
		}

		$this->ensure_table( $table );
		$this->insert_fixtures( $table );
	}

	/**
	 * Create the log table if this suite has already dropped it.
	 *
	 * Written here rather than by letting the library's handler create it, and
	 * the reason is a library detail worth recording: `DatabaseTrait` keeps
	 * private statics of which tables it has seen, with no public reset. Once
	 * a table has existed in a process, dropping it leaves the handler certain
	 * it is still there -- so every later write fails and no schema check is
	 * ever attempted again. The lifecycle tests drop this table on their way
	 * past, which puts this class on the wrong side of that.
	 *
	 * Only the columns the reader reads. This class tests the reader; that the
	 * handler writes these columns is established by the handler's own schema
	 * and by the plugin running against a real site.
	 *
	 * @param string $table Table name.
	 */
	private function ensure_table( string $table ): void {
		global $wpdb;

		$safe = '`' . str_replace( '`', '', $table ) . '`';

		/*
		 * A table name is an identifier, not a value, so it cannot be a
		 * placeholder. It comes from this plugin's own settings by way of
		 * Log_Reader::table(), and is stripped of backticks above.
		 */
		$sql = sprintf(
			<<<'SQL'
			CREATE TABLE IF NOT EXISTS %s (
				id INT UNSIGNED NOT NULL AUTO_INCREMENT,
				logged_at INT UNSIGNED NOT NULL DEFAULT 0,
				level VARCHAR(16) NOT NULL DEFAULT "",
				level_value INT UNSIGNED NOT NULL DEFAULT 0,
				channel VARCHAR(64) NOT NULL DEFAULT "",
				message LONGTEXT NOT NULL,
				request_id VARCHAR(64) NOT NULL DEFAULT "",
				client_ip VARCHAR(45) NOT NULL DEFAULT "",
				plugin_name VARCHAR(255) NOT NULL DEFAULT "",
				plugin_type VARCHAR(255) NOT NULL DEFAULT "",
				method VARCHAR(16) NOT NULL DEFAULT "",
				path LONGTEXT NOT NULL,
				host VARCHAR(255) NOT NULL DEFAULT "",
				user_agent LONGTEXT NOT NULL,
				context LONGTEXT NOT NULL,
				PRIMARY KEY (id)
			)
			SQL,
			$safe
		);

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( $sql );
	}

	/**
	 * Put this class's rows in.
	 *
	 * @param string $table Table name.
	 */
	private function insert_fixtures( string $table ): void {
		global $wpdb;

		foreach ( self::fixtures() as $fixture ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->insert(
				$table,
				array(
					'logged_at'   => time(),
					'level'       => $fixture['level'],
					'level_value' => 200,
					'channel'     => 'firewall',
					'message'     => $fixture['message'],
					'request_id'  => self::MARKER,
					'client_ip'   => '198.51.100.99',
					'plugin_name' => $fixture['rule'],
					'plugin_type' => 'Kanopi\\Firewall\\Plugins\\Url',
					'method'      => 'GET',
					'path'        => $fixture['path'],
					'host'        => 'example.test',
					'user_agent'  => 'sqlmap/1.7',
					'context'     => (string) wp_json_encode( array( 'matched' => $fixture['rule'] ) ),
				)
			);
		}
	}

	/**
	 * Take the fixture rows out again.
	 */
	protected function tearDown(): void {
		global $wpdb;

		$reader = new Log_Reader();
		$table  = $reader->table();

		// The lifecycle tests drop this table on their way past, so it may be
		// gone by the time this runs.
		if ( null !== $table && $reader->is_available() ) {
			$safe = '`' . str_replace( '`', '', $table ) . '`';

			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$safe} WHERE request_id = %s", self::MARKER ) );
		}

		parent::tearDown();
	}

	/**
	 * Rows covering the shapes the screen has to render.
	 *
	 * @return list<array{level: string, message: string, rule: string, path: string}>
	 */
	private static function fixtures(): array {
		return array(
			array(
				'level'   => 'INFO',
				'message' => 'URL matched blocking rule',
				'rule'    => 'fixture-scanners',
				'path'    => '/',
			),
			array(
				'level'   => 'NOTICE',
				'message' => 'Sending challenge response',
				'rule'    => 'fixture-challenge',
				'path'    => '/?test=1',
			),
			array(
				'level'   => 'WARNING',
				'message' => 'Request refused',
				'rule'    => 'fixture-scanners',
				'path'    => '/.env',
			),
		);
	}

	/**
	 * Only this class's own rows.
	 *
	 * @param array<string, mixed> $filters Extra filters.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function fixture_entries( array $filters = array() ): array {
		return array_values(
			array_filter(
				( new Log_Reader() )->recent( 500, $filters ),
				static fn ( array $entry ): bool => self::MARKER === $entry['request_id']
			)
		);
	}

	/**
	 * Every entry carries the detail the screen shows.
	 */
	public function test_an_entry_carries_its_detail(): void {
		$entries = $this->fixture_entries();

		$this->assertNotSame( array(), $entries, 'The fixture rows were not written.' );

		foreach ( array( 'timestamp', 'time', 'level', 'rule', 'rule_type', 'ip', 'method', 'path', 'host', 'user_agent', 'request_id', 'message', 'context' ) as $key ) {
			$this->assertArrayHasKey( $key, $entries[0], sprintf( 'The reader dropped %s, which the log screen shows.', $key ) );
		}
	}

	/**
	 * The detail is read from the columns, not guessed.
	 *
	 * Each of these has a dedicated column in the library's table, and the
	 * reader used to take three of them out of the JSON blob beside them.
	 */
	public function test_the_detail_comes_back_intact(): void {
		$entries = $this->fixture_entries();
		$found   = null;

		foreach ( $entries as $entry ) {
			if ( 'fixture-challenge' === $entry['rule'] ) {
				$found = $entry;
			}
		}

		$this->assertIsArray( $found, 'The challenge fixture did not come back.' );
		$this->assertSame( '198.51.100.99', $found['ip'] );
		$this->assertSame( 'GET', $found['method'] );
		$this->assertSame( '/?test=1', $found['path'] );
		$this->assertSame( 'example.test', $found['host'] );
		$this->assertSame( 'sqlmap/1.7', $found['user_agent'] );
		$this->assertSame( 'Sending challenge response', $found['message'] );
		$this->assertStringContainsString( 'Url', $found['rule_type'] );
	}

	/**
	 * The timestamp is read, and formatted.
	 *
	 * The bug this pins: `created_at` is not a column in this table, and
	 * reading it produced an empty When for every row without failing.
	 */
	public function test_the_time_is_populated(): void {
		foreach ( $this->fixture_entries() as $entry ) {
			$this->assertGreaterThan( 0, $entry['timestamp'], 'An entry has no timestamp, so the log cannot be filtered by when.' );
			$this->assertNotSame( '', $entry['time'], 'An entry has no formatted time, which is the When column empty.' );
		}
	}

	/**
	 * Filtering by rule returns that rule and nothing else.
	 */
	public function test_filtering_by_rule(): void {
		$entries = $this->fixture_entries( array( 'rule' => 'fixture-scanners' ) );

		$this->assertCount( 2, $entries );

		foreach ( $entries as $entry ) {
			$this->assertSame( 'fixture-scanners', $entry['rule'] );
		}
	}

	/**
	 * Filtering by level returns that level and nothing else.
	 */
	public function test_filtering_by_level(): void {
		$entries = $this->fixture_entries( array( 'level' => 'NOTICE' ) );

		$this->assertCount( 1, $entries );
		$this->assertSame( 'fixture-challenge', $entries[0]['rule'] );
	}

	/**
	 * Filtering by when excludes what is older, and everything in the future.
	 */
	public function test_filtering_by_when(): void {
		$since = time() - HOUR_IN_SECONDS;

		$this->assertCount( 3, $this->fixture_entries( array( 'since' => $since ) ) );

		foreach ( $this->fixture_entries( array( 'since' => $since ) ) as $entry ) {
			$this->assertGreaterThanOrEqual( $since, $entry['timestamp'] );
		}

		$this->assertSame(
			array(),
			$this->fixture_entries( array( 'since' => time() + HOUR_IN_SECONDS ) ),
			'A window starting in the future matched something, so the comparison is the wrong way round.'
		);
	}

	/**
	 * Filters compose rather than replace one another.
	 */
	public function test_filters_combine(): void {
		$this->assertCount(
			1,
			$this->fixture_entries(
				array(
					'rule'  => 'fixture-scanners',
					'level' => 'WARNING',
				)
			),
			'Two filters returned something other than their intersection.'
		);

		$this->assertSame(
			array(),
			$this->fixture_entries(
				array(
					'rule'  => 'fixture-challenge',
					'level' => 'WARNING',
				)
			),
			'A rule and a level that share no row returned one anyway.'
		);
	}

	/**
	 * The filter vocabularies come from what is actually in the log.
	 */
	public function test_the_filter_options_are_real(): void {
		$reader = new Log_Reader();

		$this->assertContains( 'fixture-scanners', $reader->rules() );
		$this->assertContains( 'NOTICE', $reader->levels() );

		foreach ( $reader->rules() as $rule ) {
			$this->assertNotSame( '', $rule, 'An empty rule name reached the filter, where it would read as a blank option.' );
		}

		foreach ( $reader->levels() as $level ) {
			$this->assertNotSame( '', $level );
		}
	}
}
