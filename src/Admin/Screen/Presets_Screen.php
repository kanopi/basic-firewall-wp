<?php
/**
 * Presets: shipped rule sets, enabled by reference.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;

/**
 * Switch maintained rule sets on, and read one before you do.
 */
final class Presets_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-presets';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Presets', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			__( 'Maintained rule sets shipped with the firewall library, switched on <strong>by reference</strong> rather than copied in — so they update when the library updates, and an export records only which are on rather than several hundred patterns. Preset rules cannot be edited here; to carve out an exception, add an <strong>allow</strong> rule with a lower weight, which is evaluated first and ends evaluation on a match.', 'basic-firewall' )
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$chosen    = array_map( 'strval', array_values( $this->posted_array( 'presets' ) ) );
		$available = array_keys( $this->plugin()->presets()->applicable() );

		$enabled = array_values( array_intersect( $chosen, $available ) );

		$this->plugin()->settings()->set( 'presets', $enabled );

		if ( array() !== $enabled && 'block' === (string) $this->plugin()->settings()->get( 'global.mode', 'log' ) ) {
			Notices::add(
				__( 'These rule sets are deliberately broad and will match some legitimate traffic on most sites. Consider switching to log-only mode for a few days and reading the log before leaving them enabled in Block mode.', 'basic-firewall' ),
				'warning'
			);
		}

		Notices::add( __( 'Presets saved, and the firewall recompiled.', 'basic-firewall' ) );

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		if ( '' !== $this->query( 'preset' ) ) {
			$this->render_preview();

			return;
		}

		$presets = $this->plugin()->presets()->applicable();
		$enabled = (array) $this->plugin()->settings()->get( 'presets', array() );

		if ( array() === $presets ) {
			printf( '<p>%s</p>', esc_html__( 'No presets are available.', 'basic-firewall' ) );

			return;
		}

		$this->open_form();

		echo '<table class="widefat striped"><thead><tr>';

		foreach ( array(
			__( 'Enabled', 'basic-firewall' ),
			__( 'Preset', 'basic-firewall' ),
			__( 'Source', 'basic-firewall' ),
			'',
		) as $heading ) {
			printf( '<th>%s</th>', esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $presets as $name => $preset ) {
			printf(
				'<tr><td><input type="checkbox" name="presets[]" value="%s"%s /></td><td><strong>%s</strong><br><code>%s</code></td><td>%s</td><td><a href="%s">%s</a></td></tr>',
				esc_attr( (string) $name ),
				checked( in_array( (string) $name, $enabled, true ), true, false ),
				esc_html( (string) ( $preset['label'] ?? $name ) ),
				esc_html( (string) $name ),
				esc_html( ! empty( $preset['shipped'] ) ? __( 'Firewall library', 'basic-firewall' ) : __( 'Contributed', 'basic-firewall' ) ),
				esc_url( Admin::url( $this->slug(), array( 'preset' => (string) $name ) ) ),
				esc_html__( 'View details', 'basic-firewall' )
			);
		}

		echo '</tbody></table>';

		$this->close_form( __( 'Save presets', 'basic-firewall' ) );

		$this->render_incompatible();
	}

	/**
	 * Say which rule sets are withheld on this site, and why.
	 *
	 * Named rather than silently absent. A rule set that simply is not there
	 * invites somebody to go looking for it, or to paste its contents into the
	 * Advanced screen by hand -- which is the same mistake with the guard taken
	 * off.
	 */
	private function render_incompatible(): void {
		$incompatible = $this->plugin()->presets()->incompatible();

		if ( array() === $incompatible ) {
			return;
		}

		printf( '<h2>%s</h2>', esc_html__( 'Not available on this site', 'basic-firewall' ) );

		echo '<div class="bfw-danger">';

		foreach ( $incompatible as $name => $reason ) {
			printf(
				'<p><strong><code>%s</code></strong> — %s</p>',
				esc_html( (string) $name ),
				esc_html( $reason )
			);
		}

		echo '</div>';
	}

	/**
	 * Show a preset's contents before it is switched on.
	 */
	private function render_preview(): void {
		$name   = $this->query( 'preset' );
		$preset = $this->plugin()->presets()->read( $name );

		printf( '<h2>%s</h2>', esc_html( $name ) );

		if ( null === $preset ) {
			printf( '<p>%s</p>', esc_html__( 'That preset could not be read.', 'basic-firewall' ) );

			return;
		}

		$plugins = (array) ( $preset['config']['plugins'] ?? array() );

		printf(
			'<p class="description">%s</p>',
			sprintf(
				/* translators: %d: number of rules in the preset. */
				esc_html__( '%d rule(s). These rule sets are deliberately broad — knowing what one rejects is worth a minute before finding out from the log.', 'basic-firewall' ),
				count( $plugins )
			)
		);

		foreach ( array_keys( $preset['config'] ) as $section ) {
			if ( 'plugins' === $section ) {
				continue;
			}

			printf(
				'<div class="bfw-warning"><p>%s</p></div>',
				sprintf(
					/* translators: %s: configuration section name. */
					esc_html__( 'This preset sets the "%s" section rather than only adding rules, which replaces what the matching screen has configured rather than adding to it.', 'basic-firewall' ),
					esc_html( (string) $section )
				)
			);
		}

		if ( array() !== $plugins ) {
			echo '<table class="widefat striped"><thead><tr>';

			foreach ( array(
				__( 'Rule', 'basic-firewall' ),
				__( 'Response', 'basic-firewall' ),
				__( 'Weight', 'basic-firewall' ),
				__( 'Enabled', 'basic-firewall' ),
			) as $heading ) {
				printf( '<th>%s</th>', esc_html( $heading ) );
			}

			echo '</tr></thead><tbody>';

			foreach ( $plugins as $rule ) {
				if ( ! is_array( $rule ) ) {
					continue;
				}

				printf(
					'<tr><td><code>%s</code></td><td>%s</td><td>%d</td><td>%s</td></tr>',
					esc_html( (string) ( $rule['metadata']['name'] ?? $rule['plugin'] ?? '' ) ),
					esc_html( (string) ( $rule['response'] ?? 'block' ) ),
					(int) ( $rule['weight'] ?? 0 ),
					// A rule shipping switched off stays off: enabling the preset
					// does not switch it on.
					empty( $rule['enable'] ) ? esc_html__( 'No — ships disabled', 'basic-firewall' ) : esc_html__( 'Yes', 'basic-firewall' )
				);
			}

			echo '</tbody></table>';
		}

		printf( '<h2>%s</h2>', esc_html__( 'The file', 'basic-firewall' ) );

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Comments included — they are frequently the clearest explanation of why a pattern is there.', 'basic-firewall' )
		);

		printf( '<pre class="bfw-code">%s</pre>', esc_html( $preset['raw'] ) );

		printf(
			'<p><a href="%s" class="button">%s</a></p>',
			esc_url( Admin::url( $this->slug() ) ),
			esc_html__( 'Back to presets', 'basic-firewall' )
		);
	}
}
