<?php
/**
 * Transient admin messages.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin;

/**
 * Messages that survive the redirect after a submission.
 *
 * Stored per user rather than globally: two administrators saving at once must
 * not read each other's confirmations, and "Settings saved" appearing on
 * somebody else's screen is the sort of thing that gets reported as a bug years
 * later.
 */
final class Notices {

	/**
	 * Queue a message.
	 *
	 * @param string $message Message text.
	 * @param string $type    One of success, error, warning, info.
	 */
	public static function add( string $message, string $type = 'success' ): void {
		$key   = self::key();
		$queue = get_transient( $key );

		if ( ! is_array( $queue ) ) {
			$queue = array();
		}

		$queue[] = array(
			'message' => $message,
			'type'    => in_array( $type, array( 'success', 'error', 'warning', 'info' ), true ) ? $type : 'info',
		);

		set_transient( $key, $queue, 60 );
	}

	/**
	 * Print and clear the queue.
	 */
	public static function render(): void {
		$key   = self::key();
		$queue = get_transient( $key );

		if ( ! is_array( $queue ) || array() === $queue ) {
			return;
		}

		delete_transient( $key );

		foreach ( $queue as $notice ) {
			printf(
				'<div class="notice notice-%s is-dismissible"><p>%s</p></div>',
				esc_attr( (string) $notice['type'] ),
				wp_kses_post( (string) $notice['message'] )
			);
		}
	}

	/**
	 * The current user's queue key.
	 */
	private static function key(): string {
		return 'basic_firewall_notices_' . get_current_user_id();
	}
}
