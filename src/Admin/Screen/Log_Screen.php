<?php
/**
 * The log report.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Logging\Log_Reader;

/**
 * What the firewall has been doing.
 */
final class Log_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-log';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Firewall log', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Log', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function capability(): string {
		return Capabilities::VIEW_REPORTS;
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$reader = new Log_Reader();

		if ( ! $reader->is_available() ) {
			printf(
				'<div class="bfw-warning"><p>%s</p><p>%s</p></div>',
				esc_html__( 'There is no readable log to show.', 'basic-firewall' ),
				sprintf(
					/* translators: %s: URL of the logging screen. */
					wp_kses_post( __( 'Enable a <strong>Database table</strong> handler on the <a href="%s">Logging screen</a> to read events back here. A file handler answers "what happened just now" if you can reach a shell; a table answers the questions that actually get asked — which rule has blocked the most clients this week, whether a rule has matched anything at all since it was added, what the firewall did to an address before its owner complained.', 'basic-firewall' ) ),
					esc_url( Admin::url( 'basic-firewall-logging' ) )
				)
			);

			return;
		}

		$entries = $reader->recent( 200 );

		if ( array() === $entries ) {
			printf( '<p>%s</p>', esc_html__( 'The log is empty.', 'basic-firewall' ) );

			return;
		}

		echo '<table class="widefat striped"><thead><tr>';

		foreach ( array(
			__( 'When', 'basic-firewall' ),
			__( 'Level', 'basic-firewall' ),
			__( 'Rule', 'basic-firewall' ),
			__( 'Client', 'basic-firewall' ),
			__( 'Message', 'basic-firewall' ),
		) as $heading ) {
			printf( '<th>%s</th>', esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $entries as $entry ) {
			printf(
				'<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>',
				esc_html( (string) ( $entry['time'] ?? '' ) ),
				esc_html( (string) ( $entry['level'] ?? '' ) ),
				esc_html( (string) ( $entry['rule'] ?? '' ) ),
				esc_html( (string) ( $entry['ip'] ?? '' ) ),
				esc_html( (string) ( $entry['message'] ?? '' ) )
			);
		}

		echo '</tbody></table>';
	}
}
