<?php
/**
 * Export the configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Transfer\Exporter;

/**
 * A portable document, safe to hand to somebody else.
 */
final class Export_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-export';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Export', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			/* translators: %s: the value described in the sentence. */
			__( 'WordPress has no configuration deployment story of its own, so this is it. The document below moves a rule set to another site, or into a ticket. <strong>Credentials are stripped and the document says which</strong> — an <code>%env(NAME)%</code> token names a variable rather than holding a secret, so tokens survive intact.', 'basic-firewall' )
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		if ( '' === $this->posted( 'download' ) ) {
			return;
		}

		header( 'Content-Type: text/yaml; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="basic-firewall-' . gmdate( 'Ymd-His' ) . '.yml"' );

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo ( new Exporter() )->to_yaml();

		exit;
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$exporter = new Exporter();
		$export   = $exporter->export();

		if ( array() !== $export['redacted'] ) {
			printf(
				'<div class="bfw-warning"><p><strong>%s</strong></p><ul style="list-style:disc;margin-left:2em"><li>%s</li></ul><p>%s</p></div>',
				esc_html__( 'These credentials were removed from the export:', 'basic-firewall' ),
				wp_kses_post( implode( '</li><li>', array_map( 'esc_html', $export['redacted'] ) ) ),
				esc_html__( 'A site importing this keeps whatever it already has for them — importing will not blank them — but a site that has none will need them supplied by hand.', 'basic-firewall' )
			);
		}

		$this->open_form();

		printf( '<input type="hidden" name="download" value="1" />' );

		submit_button( __( 'Download the document', 'basic-firewall' ) );

		echo '</form>';

		printf( '<h2>%s</h2>', esc_html__( 'The document', 'basic-firewall' ) );
		printf( '<pre class="bfw-code">%s</pre>', esc_html( $exporter->to_yaml() ) );
	}
}
