<?php
/**
 * Reads firewall events back out of the log table.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Logging;

use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Plugin;

/**
 * The log report's data source.
 *
 * Only the database handler is readable. A file handler answers "what happened
 * just now" if you can reach a shell; a table answers the questions that
 * actually get asked -- which rule has blocked the most clients this week,
 * whether a rule has matched anything at all since it was added, what the
 * firewall did to an address before its owner complained.
 *
 * Reads go through `$wpdb` rather than through Doctrine, because by the time the
 * admin screen runs WordPress exists and `$wpdb` is the connection the site is
 * already using. The *writes* go through the library, which has no WordPress --
 * so the two halves reach the same table by different routes, and the table name
 * has to be prefixed identically by both.
 */
final class Log_Reader {

	/**
	 * The configured log table, or null when no database handler is enabled.
	 */
	public function table(): ?string {
		foreach ( (array) Plugin::instance()->settings()->get( 'logger', array() ) as $handler ) {
			if ( ! is_array( $handler ) || empty( $handler['enabled'] ) || 'database' !== ( $handler['type'] ?? '' ) ) {
				continue;
			}

			$table = (string) ( $handler['table'] ?? 'basic_firewall_log' );

			// Only readable here when it lives in WordPress's own database.
			if ( 'wordpress' !== (string) ( $handler['connection_source'] ?? 'wordpress' ) ) {
				return null;
			}

			return ( new Database_Credentials() )->prefix_table( $table );
		}

		return null;
	}

	/**
	 * Whether there is a log to read.
	 */
	public function is_available(): bool {
		global $wpdb;

		$table = $this->table();

		if ( null === $table ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );

		return is_string( $found ) && '' !== $found;
	}

	/**
	 * The most recent entries, optionally filtered.
	 *
	 * @param int                  $limit   How many.
	 * @param array<string, mixed> $filters Rule, level, and since as a timestamp.
	 *
	 * @return list<array<string, mixed>>
	 */
	public function recent( int $limit = 200, array $filters = array() ): array {
		global $wpdb;

		$table = $this->table();

		if ( null === $table || ! $this->is_available() ) {
			return array();
		}

		$limit = max( 1, min( 1000, $limit ) );
		$safe  = $this->quoted_table( $table );

		list( $where, $parameters ) = $this->where( $filters );

		$parameters[] = $limit;

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT * FROM {$safe} {$where} ORDER BY id DESC LIMIT %d", $parameters ),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$entries = array();

		foreach ( $rows as $row ) {
			$context = json_decode( (string) ( $row['context'] ?? '{}' ), true );
			$context = is_array( $context ) ? $context : array();

			/*
			 * Read from the columns, falling back to the context.
			 *
			 * The library gives this table dedicated columns for everything
			 * worth asking about -- who, what they asked for, which rule
			 * answered -- and this method used to read three of them out of the
			 * JSON blob instead. `time` was read from `created_at`, a column
			 * that does not exist, so the When column on the log screen was
			 * empty for every row ever written.
			 */
			$logged = (int) ( $row['logged_at'] ?? 0 );

			$entries[] = array(
				'id'         => (int) ( $row['id'] ?? 0 ),
				'timestamp'  => $logged,
				'time'       => $logged > 0 ? wp_date( 'Y-m-d H:i:s', $logged ) : '',
				'level'      => (string) ( $row['level'] ?? $context['level'] ?? '' ),
				'rule'       => (string) ( $row['plugin_name'] ?? $context['name'] ?? '' ),
				'rule_type'  => (string) ( $row['plugin_type'] ?? '' ),
				'ip'         => (string) ( $row['client_ip'] ?? $context['client_ip'] ?? '' ),
				'method'     => (string) ( $row['method'] ?? '' ),
				'path'       => (string) ( $row['path'] ?? '' ),
				'host'       => (string) ( $row['host'] ?? '' ),
				'user_agent' => (string) ( $row['user_agent'] ?? '' ),
				'request_id' => (string) ( $row['request_id'] ?? '' ),
				'message'    => (string) ( $row['message'] ?? '' ),
				'context'    => $context,
			);
		}

		return $entries;
	}

	/**
	 * The rules that appear in the log, for the filter.
	 *
	 * Read from the log rather than from the settings, deliberately: the useful
	 * question is "which rules have actually fired", and a rule deleted last
	 * week is still the reason a client was blocked last week.
	 *
	 * @return list<string>
	 */
	public function rules(): array {
		return $this->distinct( 'plugin_name' );
	}

	/**
	 * The levels that appear in the log, for the filter.
	 *
	 * @return list<string>
	 */
	public function levels(): array {
		return $this->distinct( 'level' );
	}

	/**
	 * Distinct non-empty values of one column.
	 *
	 * @param string $column Column name, from this class only.
	 *
	 * @return list<string>
	 */
	private function distinct( string $column ): array {
		global $wpdb;

		$table = $this->table();

		if ( null === $table || ! $this->is_available() ) {
			return array();
		}

		$safe   = $this->quoted_table( $table );
		$column = '`' . str_replace( '`', '', $column ) . '`';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$values = $wpdb->get_col( "SELECT DISTINCT {$column} FROM {$safe} WHERE {$column} != '' ORDER BY {$column} ASC" );

		return is_array( $values ) ? array_values( array_map( 'strval', $values ) ) : array();
	}

	/**
	 * Build the WHERE clause and its parameters.
	 *
	 * Every filter is a value rather than an identifier, so every one of them
	 * is parameterised. The table name is the only thing here that cannot be,
	 * and it is quoted rather than trusted -- see quoted_table().
	 *
	 * @param array<string, mixed> $filters Rule, level and since.
	 *
	 * @return array{0: string, 1: list<mixed>}
	 */
	private function where( array $filters ): array {
		$clauses    = array();
		$parameters = array();

		$rule = trim( (string) ( $filters['rule'] ?? '' ) );

		if ( '' !== $rule ) {
			$clauses[]    = 'plugin_name = %s';
			$parameters[] = $rule;
		}

		$level = trim( (string) ( $filters['level'] ?? '' ) );

		if ( '' !== $level ) {
			$clauses[]    = 'level = %s';
			$parameters[] = $level;
		}

		$since = (int) ( $filters['since'] ?? 0 );

		if ( $since > 0 ) {
			$clauses[]    = 'logged_at >= %d';
			$parameters[] = $since;
		}

		return array(
			array() === $clauses ? '' : 'WHERE ' . implode( ' AND ', $clauses ),
			$parameters,
		);
	}

	/**
	 * The table name, quoted for interpolation.
	 *
	 * The name is assembled from a stored setting plus this site's prefix, so
	 * it cannot be parameterised -- an identifier is not a value. It is passed
	 * through esc_sql() and stripped of backticks rather than trusted, because
	 * the stored value reaches here from an imported document as readily as
	 * from the form.
	 *
	 * @param string $table Table name.
	 */
	private function quoted_table( string $table ): string {
		return '`' . str_replace( '`', '', esc_sql( $table ) ) . '`';
	}
}
