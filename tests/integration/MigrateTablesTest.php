<?php
/**
 * Bringing an existing table up to the schema the library declares.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Plugin;

/**
 * A log table written before library 2.37.0 gains the indexes it added.
 *
 * The library creates a table on first write and never alters it after, so
 * the two indexes by rule that 2.37.0 added (kanopi/firewall#458) reach an
 * existing site only when something migrates it. A plugin user has no
 * `bin/firewall-migrate`; Runner::migrate_tables() is what they have, behind
 * `wp basic-firewall migrate` and the Logging screen's button.
 *
 * @covers \Kanopi\BasicFirewall\Runtime\Runner::migrate_tables
 */
final class MigrateTablesTest extends Honoured_Settings {

	/**
	 * The log table, unprefixed.
	 */
	private const TABLE = 'migrate_test_log';

	/**
	 * Drop the table this class created.
	 */
	protected function tearDown(): void {
		global $wpdb;

		$table = $this->table();

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- test cleanup of a table this test created.
		$wpdb->query( "DROP TABLE IF EXISTS `$table`" );

		parent::tearDown();
	}

	/**
	 * Missing indexes are reported by a dry run, added by a real one, and then gone.
	 */
	public function test_a_table_missing_the_rule_indexes_gains_them(): void {
		global $wpdb;

		$this->build(
			array(
				'logger' => array(
					array(
						'type'              => 'database',
						'enabled'           => true,
						'level'             => 'warning',
						'table'             => self::TABLE,
						'connection_source' => 'wordpress',
					),
				),
			)
		);

		$runner = Plugin::instance()->runner();
		$table  = $this->table();

		// Built, so the table exists with this release's schema, both indexes included.
		$this->assertSame( array(), $this->changes_for( $runner->migrate_tables( false ), $table ) );

		// Now as a table written before 2.37.0 would be.
		foreach ( array( 'plugin_name_logged_at', 'logged_at_plugin_name' ) as $column ) {
			$index = "{$table}_{$column}_idx";

			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- a table this test created.
			$wpdb->query( "DROP INDEX `$index` ON `$table`" );
		}

		$pending = $this->changes_for( $runner->migrate_tables( false ), $table );

		$this->assertSame(
			array( $table . '_logged_at_plugin_name_idx', $table . '_plugin_name_logged_at_idx' ),
			self::sorted( array_column( $pending, 'name' ) ),
			'A dry run did not report the two missing indexes.'
		);

		$applied = $this->changes_for( $runner->migrate_tables( true ), $table );

		$this->assertCount( 2, $applied );
		$this->assertSame( array( true, true ), array_map( static fn ( array $change ): bool => ! empty( $change['applied'] ), $applied ) );
		$this->assertSame( array(), $this->changes_for( $runner->migrate_tables( false ), $table ), 'The indexes are still missing after the migration.' );
	}

	/**
	 * The changes a report names for one table.
	 *
	 * @param array<string, mixed>|null $report What migrate_tables() returned.
	 * @param string                    $table  The table.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function changes_for( ?array $report, string $table ): array {
		$this->assertNotNull( $report, 'The configuration could not be loaded.' );
		$this->assertSame( array(), $report['failures'] );

		return array_values(
			array_filter(
				$report['changes'],
				static fn ( array $change ): bool => $table === $change['table']
			)
		);
	}

	/**
	 * The table, with this site's prefix.
	 */
	private function table(): string {
		return ( new Database_Credentials() )->prefix_table( self::TABLE );
	}

	/**
	 * A list, sorted.
	 *
	 * @param list<string> $values Values.
	 *
	 * @return list<string>
	 */
	private static function sorted( array $values ): array {
		sort( $values );

		return $values;
	}
}
