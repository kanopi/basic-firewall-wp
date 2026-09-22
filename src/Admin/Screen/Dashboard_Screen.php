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
		/*
		 * "Status", not "Dashboard". A dashboard is a place; this is an answer
		 * -- whether the firewall is on, what it is doing, and whether anything
		 * about that needs attention. The word somebody scans the sidebar for
		 * when they want to know if something is wrong.
		 */
		return __( 'Status', 'basic-firewall' );
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
		$this->render_evaluation_point();
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
	 * Where the firewall runs, and how to move it earlier.
	 *
	 * This exists because the wp-config.php snippet used to appear in exactly
	 * one place: a Site Health test that only fires when a page cache is
	 * detected. Somebody without a page cache -- or with one the detector does
	 * not recognise -- had no way to find it short of reading the README, and
	 * the snippet is not something they can write themselves either, because
	 * the private directory carries a random per-site suffix.
	 */
	private function render_evaluation_point(): void {
		if ( ! Admin::can_manage() ) {
			return;
		}

		/*
		 * Nothing to say when there is nothing to do.
		 *
		 * The Checks table directly above already reports both of these, so on
		 * a correctly configured site this section restated a passing result
		 * and then printed a block of configuration under it -- which reads as
		 * an instruction whatever the sentence above it says. A panel that only
		 * appears when it has something to tell you is a panel worth reading
		 * when it does.
		 */
		$results = Site_Health::results();

		if ( 'good' === $results['bootstrap']['status'] && 'good' === $results['evaluation']['status'] ) {
			return;
		}

		$early = defined( 'BASIC_FIREWALL_EVALUATED' );
		$mu    = is_readable( WPMU_PLUGIN_DIR . '/basic-firewall-loader.php' );

		printf( '<h2>%s</h2>', esc_html__( 'Evaluation point', 'basic-firewall' ) );

		if ( $early ) {
			$where = __( 'wp-config.php, before WordPress loads. This is the earliest any PHP on this site can act, and a page cache cannot serve a request without it being evaluated first.', 'basic-firewall' );
		} elseif ( $mu ) {
			$where = __( 'An mu-plugin, before plugins and the theme load. That is as early as a plugin can act — but a page cache serving from advanced-cache.php runs earlier still, and a cache hit is never evaluated.', 'basic-firewall' );
		} else {
			$where = __( 'Once every plugin has loaded, which is later than it should be. The mu-plugin loader is not installed; deactivating and reactivating the plugin will try again.', 'basic-firewall' );
		}

		printf( '<p>%s</p>', esc_html( $where ) );

		/*
		 * The fallback is stated even when it is not the path in use. Somebody
		 * reading this section is answering "where does this run?", and the
		 * honest answer includes what happens when the line in wp-config.php
		 * stops being there -- which a deployment, a restore or a host that
		 * regenerates the file all do without announcing it.
		 */
		if ( $early ) {
			printf(
				'<p class="%s">%s</p>',
				$mu ? 'description' : 'bfw-warning',
				esc_html(
					$mu
						? __( 'The mu-plugin fallback is installed, so evaluation stays early even if the snippet below is ever removed.', 'basic-firewall' )
						: __( 'The mu-plugin fallback is not installed. Nothing is wrong as things stand — the wp-config.php path is earlier than the fallback and supersedes it — but if that snippet goes away, the firewall drops to running after every plugin has loaded, and looks identical here when it does. Deactivating and reactivating the plugin reinstalls it.', 'basic-firewall' )
				)
			);
		}

		$placement = __( 'Place it below the DB_NAME, DB_USER, DB_PASSWORD and DB_HOST definitions and immediately above the line that requires wp-settings.php. Below them, database-backed block storage keeps working on this path; above them, it cannot be reached and the firewall fails open on every request.', 'basic-firewall' );
		$snippet   = sprintf( '<pre class="bfw-snippet">%s</pre>', esc_html( Site_Health::bootstrap_snippet() ) );

		/*
		 * Folded away once the snippet is in place.
		 *
		 * Printed open in both states, it read as an instruction on a site that
		 * had already followed it -- a block of configuration sitting under a
		 * heading, which is the shape of something still to do. The sentence
		 * above it said "currently in use", and nobody reads the sentence when
		 * the page is showing them a code block. It is still one click away,
		 * because re-checking the exact line is the reason to come here.
		 */
		if ( $early ) {
			printf(
				'<details><summary>%s</summary><p class="description">%s</p>%s<p class="description">%s</p></details>',
				esc_html__( 'Show the snippet currently in use', 'basic-firewall' ),
				esc_html__( 'This is what wp-config.php should contain. The path is specific to this site — the private directory carries a random suffix.', 'basic-firewall' ),
				wp_kses_post( $snippet ),
				esc_html( $placement )
			);

			return;
		}

		printf(
			'<p>%s</p>',
			esc_html__( 'To move it earlier, add this to wp-config.php. The path is specific to this site — the private directory carries a random suffix, so this cannot be copied between environments.', 'basic-firewall' )
		);

		echo wp_kses_post( $snippet );

		printf( '<p class="description">%s</p>', esc_html( $placement ) );
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
			'basic-firewall-rules'    => __( 'Rules', 'basic-firewall' ),
			'basic-firewall-test'     => __( 'Test a request', 'basic-firewall' ),
			'basic-firewall-blocked'  => __( 'Blocked clients', 'basic-firewall' ),
			'basic-firewall-compiled' => __( 'Compiled configuration', 'basic-firewall' ),
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
