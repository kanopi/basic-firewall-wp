<?php
/**
 * View the compiled configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;

/**
 * Exactly what the firewall loaded.
 *
 * Worth having its own screen rather than being a debugging aid: when a rule
 * does nothing, this is the fastest way to see whether it compiled to what its
 * author expected, and it is the only place that shows what a preset actually
 * contributed.
 *
 * Rebuilding lives here too, rather than on a page of its own. A page whose
 * whole content is one button is a page somebody has to already know about,
 * and the moment anybody wants that button is the moment they are looking at
 * this screen: the file is missing, or older than the change they just made,
 * or does not say what they expected. Putting the two together means the
 * question and the answer are never one navigation apart.
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
	 * Rebuild on demand.
	 *
	 * Settings saves recompile by themselves; this is for after a deployment, a
	 * restore, or a manual change to the private directory.
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$result = $this->plugin()->compiled()->rebuild();

		foreach ( $result['problems'] as $problem ) {
			Notices::add( esc_html( $problem ), 'warning' );
		}

		if ( ! $result['written'] ) {
			Notices::add(
				__( 'The configuration could not be compiled. The firewall is running on whatever was compiled before — or, if there was nothing, on nothing at all.', 'basic-firewall' ),
				'error'
			);
		} elseif ( array() !== $result['problems'] ) {
			// Not "Success". A rebuild that skipped a rule has produced a
			// firewall enforcing less than is configured.
			Notices::add(
				__( 'Rebuilt, but with problems. The firewall is enforcing less than is configured — see the warnings above.', 'basic-firewall' ),
				'warning'
			);
		} else {
			Notices::add( __( 'The firewall has been rebuilt.', 'basic-firewall' ) );
		}

		$this->redirect( $this->slug() );
	}

	/**
	 * The rebuild control.
	 *
	 * Printed by both branches of render(), because the branch where there is
	 * no compiled file to show is the one where it is most needed.
	 */
	private function render_rebuild(): void {
		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Recompiles your settings into this file and warms the library\'s parse cache, so the next visitor does not pay for the first parse. Settings saves already do this; rebuild by hand after a deployment, a restore, or a change made directly to the private directory.', 'basic-firewall' )
		);

		$this->open_form();
		$this->close_form( __( 'Rebuild now', 'basic-firewall' ) );
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

			$this->render_rebuild();

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

		printf( '<h2>%s</h2>', esc_html__( 'Rebuild', 'basic-firewall' ) );

		$this->render_rebuild();
	}
}
