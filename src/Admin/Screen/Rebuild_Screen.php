<?php
/**
 * Rebuild the compiled configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;

/**
 * Recompile on demand.
 */
final class Rebuild_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-rebuild';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Rebuild the firewall', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Rebuild', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return esc_html__( 'Recompiles your settings into the file the firewall reads, and warms the library\'s parse cache so the next visitor does not pay for it. This happens automatically whenever settings are saved — it is here for after a deployment, a restore, or a manual change to the private directory.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
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
	 * {@inheritDoc}
	 */
	public function render(): void {
		$this->open_form();
		$this->close_form( __( 'Rebuild now', 'basic-firewall' ) );
	}
}
