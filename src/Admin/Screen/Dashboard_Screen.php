<?php
/**
 * The firewall dashboard.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Library_Loader;

/**
 * What the firewall is doing right now.
 */
final class Dashboard_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Basic Firewall', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Dashboard', 'basic-firewall' );
	}

	/**
	 * Reading the dashboard is not configuring the firewall.
	 *
	 * {@inheritDoc}
	 */
	public function capability(): string {
		return Capabilities::VIEW_REPORTS;
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$plugin   = $this->plugin();
		$settings = $plugin->settings();

		$mode    = (string) $settings->get( 'global.mode', 'log' );
		$enabled = $plugin->runner()->is_enabled();

		echo '<div class="bfw-cards">';

		$this->card(
			__( 'Status', 'basic-firewall' ),
			$this->status_line( $enabled, $mode ),
			$enabled && 'block' === $mode ? 'good' : 'recommended'
		);

		$this->card(
			__( 'Rules', 'basic-firewall' ),
			sprintf(
				/* translators: 1: number of rules, 2: number of presets. */
				esc_html__( '%1$d configured, %2$d preset(s) enabled', 'basic-firewall' ),
				count( (array) $settings->get( 'rules', array() ) ),
				count( (array) $settings->get( 'presets', array() ) )
			),
			'good'
		);

		$blocked = $plugin->blocked()->all();

		$this->card(
			__( 'Blocked clients', 'basic-firewall' ),
			$blocked['supported']

				/* translators: %d: number of blocked clients. */
				? sprintf( esc_html__( '%d currently blocked', 'basic-firewall' ), count( $blocked['clients'] ) )
				: esc_html__( 'This storage backend cannot list what it holds', 'basic-firewall' ),
			'good'
		);

		$this->card(
			__( 'Library', 'basic-firewall' ),
			sprintf(
				'kanopi/firewall %s',
				esc_html( (string) ( Library_Loader::version() ?? __( 'not loaded', 'basic-firewall' ) ) )
			),
			Library_Loader::is_usable() ? 'good' : 'critical'
		);

		echo '</div>';

		$this->render_health();
		$this->render_shortcuts();
	}

	/**
	 * A one-line summary of what is happening to traffic.
	 *
	 * @param bool   $enabled Whether the firewall runs.
	 * @param string $mode    Operating mode.
	 */
	private function status_line( bool $enabled, string $mode ): string {
		if ( ! $enabled ) {
			return esc_html__( 'Switched off — nothing is evaluated', 'basic-firewall' );
		}

		return match ( $mode ) {
			'block'     => esc_html__( 'Blocking matching requests', 'basic-firewall' ),
			'log'       => esc_html__( 'Log only — matches recorded, nothing blocked', 'basic-firewall' ),
			'exception' => esc_html__( 'Exception mode — for testing', 'basic-firewall' ),
			default     => esc_html__( 'Evaluating nothing', 'basic-firewall' ),
		};
	}

	/**
	 * Print one card.
	 *
	 * @param string $title  Card title.
	 * @param string $body   Card body, already escaped.
	 * @param string $status One of good, recommended, critical.
	 */
	private function card( string $title, string $body, string $status ): void {
		printf(
			'<div class="bfw-card bfw-card--%s"><h2>%s</h2><p>%s</p></div>',
			esc_attr( $status ),
			esc_html( $title ),
			wp_kses_post( $body )
		);
	}

	/**
	 * Surface the Site Health results here too.
	 *
	 * The dashboard is the page somebody opens when they are already thinking
	 * about the firewall, so the findings belong on it rather than only on a
	 * page they have to know to visit.
	 */
	private function render_health(): void {
		printf( '<h2>%s</h2>', esc_html__( 'Checks', 'basic-firewall' ) );

		echo '<table class="widefat striped"><tbody>';

		foreach ( Site_Health::results() as $result ) {
			$icon = match ( $result['status'] ) {
				'critical'    => '&#10007;',
				'recommended' => '&#9888;',
				default       => '&#10003;',
			};

			printf(
				'<tr><td style="width:2rem">%s</td><td><strong>%s</strong>%s</td></tr>',
				esc_html( $icon ),
				esc_html( $result['label'] ),
				'good' === $result['status'] ? '' : wp_kses_post( $result['description'] )
			);
		}

		echo '</tbody></table>';
	}

	/**
	 * Links to the screens somebody reaches for from here.
	 */
	private function render_shortcuts(): void {
		if ( ! Admin::can_manage() ) {
			return;
		}

		printf( '<h2>%s</h2><p>', esc_html__( 'Next', 'basic-firewall' ) );

		$links = array(
			'basic-firewall-rules'   => __( 'Rules', 'basic-firewall' ),
			'basic-firewall-test'    => __( 'Test a request', 'basic-firewall' ),
			'basic-firewall-blocked' => __( 'Blocked clients', 'basic-firewall' ),
			'basic-firewall-rebuild' => __( 'Rebuild', 'basic-firewall' ),
		);

		foreach ( $links as $slug => $label ) {
			printf(
				'<a href="%s" class="button">%s</a> ',
				esc_url( Admin::url( $slug ) ),
				esc_html( $label )
			);
		}

		echo '</p>';
	}
}
