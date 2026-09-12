<?php
/**
 * View the compiled configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Screen;

/**
 * Exactly what the firewall loaded.
 *
 * Worth having its own screen rather than being a debugging aid: when a rule
 * does nothing, this is the fastest way to see whether it compiled to what its
 * author expected, and it is the only place that shows what a preset actually
 * contributed.
 */
final class Compiled_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-compiled';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Compiled configuration', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Compiled', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return esc_html__( 'The file the firewall actually reads. It is a cache of your settings, rewritten whenever they are saved, and it is safe to delete. Do not edit it — anything changed here is overwritten on the next rebuild.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$compiled = $this->plugin()->compiled();
		$contents = $compiled->contents();

		if ( null === $contents ) {
			printf(
				'<div class="bfw-danger"><p>%s</p></div>',
				esc_html__( 'There is no compiled configuration. No rules are being enforced — every request is currently allowed through. Rebuild the firewall to recreate it.', 'basic-firewall' )
			);

			return;
		}

		$meta = $compiled->meta();

		printf(
			'<p><code>%s</code><br>%s</p>',
			esc_html( $this->plugin()->paths()->compiled_file() ),
			esc_html(
				sprintf(
					/* translators: %s: human-readable time difference. */
					__( 'Compiled %s ago.', 'basic-firewall' ),
					human_time_diff( (int) ( $meta['compiled_at'] ?? time() ) )
				)
			)
		);

		$paths = $compiled->connection_paths();

		if ( array() !== $paths ) {
			printf(
				'<p class="description">%s <code>%s</code></p>',
				esc_html__( 'Database credentials are deliberately absent from this file. They are injected at these paths on every request:', 'basic-firewall' ),
				esc_html( implode( ', ', $paths ) )
			);
		}

		printf( '<pre class="bfw-code">%s</pre>', esc_html( $contents ) );
	}
}
