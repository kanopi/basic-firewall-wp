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
	 * The most recent entries.
	 *
	 * @param int $limit How many.
	 *
	 * @return list<array<string, mixed>>
	 */
	public function recent( int $limit = 200 ): array {
		global $wpdb;

		$table = $this->table();

		if ( null === $table || ! $this->is_available() ) {
			return array();
		}

		$limit = max( 1, min( 1000, $limit ) );

		/*
		 * The table name is assembled from a stored setting plus this site's
		 * prefix, so it cannot be parameterised -- an identifier is not a value.
		 * It is passed through esc_sql() and stripped of backticks rather than
		 * trusted, because the stored value reaches here from an imported
		 * document as readily as from the form.
		 */
		$safe = '`' . str_replace( '`', '', esc_sql( $table ) ) . '`';

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$wpdb->prepare( "SELECT * FROM {$safe} ORDER BY id DESC LIMIT %d", $limit ),
			ARRAY_A
		);

		if ( ! is_array( $rows ) ) {
			return array();
		}

		$entries = array();

		foreach ( $rows as $row ) {
			$context = json_decode( (string) ( $row['context'] ?? '{}' ), true );
			$context = is_array( $context ) ? $context : array();

			$entries[] = array(
				'time'    => (string) ( $row['created_at'] ?? $row['time'] ?? '' ),
				'level'   => (string) ( $row['level_name'] ?? $row['level'] ?? '' ),
				'rule'    => (string) ( $context['name'] ?? $context['plugin'] ?? '' ),
				'ip'      => (string) ( $context['ip'] ?? $context['client_ip'] ?? '' ),
				'message' => (string) ( $row['message'] ?? '' ),
				'context' => $context,
			);
		}

		return $entries;
	}
}
