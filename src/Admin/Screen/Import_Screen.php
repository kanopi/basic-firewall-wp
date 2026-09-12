<?php
/**
 * Import a configuration document.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Transfer\Importer;

/**
 * Read a document back in, previewing before applying.
 */
final class Import_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-import';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Import', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return wp_kses_post(
			__( 'Paste a document exported from this or another site. <strong>An empty credential means "not carried", never "set to nothing"</strong> — importing a stripped export will not erase this site\'s own secrets. Rules are matched by identifier, not by position.', 'basic-firewall' )
		);
	}

	/**
	 * The document held between preview and apply.
	 */
	private const PENDING = 'basic_firewall_pending_import';

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$action = $this->posted( 'import_action' );
		$mode   = $this->posted( 'mode', 'merge' );

		if ( 'apply' === $action ) {
			$this->apply( $mode );

			return;
		}

		$document = $this->posted_textarea( 'document' );

		if ( '' === trim( $document ) ) {
			Notices::add( __( 'Paste a document to import.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		$preview = ( new Importer() )->preview( $document, $mode );

		if ( ! $preview['ok'] ) {
			Notices::add( esc_html( (string) $preview['error'] ), 'error' );

			$this->redirect( $this->slug() );
		}

		// Held per user for the length of the confirmation, not written to
		// settings -- a preview must change nothing.
		set_transient( self::PENDING . '_' . get_current_user_id(), $document, 15 * MINUTE_IN_SECONDS );

		$this->redirect(
			$this->slug(),
			array(
				'preview' => '1',
				'mode'    => $mode,
			)
		);
	}

	/**
	 * Apply the held document.
	 *
	 * @param string $mode Import mode.
	 */
	private function apply( string $mode ): void {
		$key      = self::PENDING . '_' . get_current_user_id();
		$document = get_transient( $key );

		if ( ! is_string( $document ) || '' === $document ) {
			Notices::add( __( 'The document is no longer held. Paste it again.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		delete_transient( $key );

		$result = ( new Importer() )->import( $document, $mode );

		if ( ! $result['ok'] ) {
			Notices::add( esc_html( (string) $result['error'] ), 'error' );

			$this->redirect( $this->slug() );
		}

		foreach ( $result['problems'] as $problem ) {
			Notices::add( sprintf( '<strong>%s</strong>: %s', esc_html( $problem['path'] ), esc_html( $problem['message'] ) ), 'warning' );
		}

		Notices::add( __( 'Configuration imported, and the firewall recompiled.', 'basic-firewall' ) );

		$this->redirect( 'basic-firewall-rules' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		if ( '1' === $this->query( 'preview' ) ) {
			$this->render_preview();

			return;
		}

		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Document', 'basic-firewall' ),
			self::textarea( 'document', '', 18 )
		);

		$this->row(
			__( 'Mode', 'basic-firewall' ),
			self::select(
				'mode',
				array(
					'merge'   => __( 'Merge — add and update, keep everything else', 'basic-firewall' ),
					'replace' => __( 'Replace — use this document\'s rule set instead of the current one', 'basic-firewall' ),
				),
				'merge'
			),
			__( 'Replace governs the rule set and the sections the document carries. It does not reset settings the document does not mention — a document that only carries rules will not silently revert your storage, logging and challenge configuration.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		printf( '<input type="hidden" name="import_action" value="preview" />' );

		$this->close_form( __( 'Preview the import', 'basic-firewall' ) );
	}

	/**
	 * Show what the import would do.
	 */
	private function render_preview(): void {
		$document = get_transient( self::PENDING . '_' . get_current_user_id() );
		$mode     = $this->query( 'mode', 'merge' );

		if ( ! is_string( $document ) || '' === $document ) {
			printf( '<p>%s</p>', esc_html__( 'The document is no longer held. Paste it again.', 'basic-firewall' ) );

			$this->render_form_again();

			return;
		}

		$preview = ( new Importer() )->preview( $document, $mode );

		if ( ! $preview['ok'] ) {
			printf( '<div class="bfw-danger"><p>%s</p></div>', esc_html( (string) $preview['error'] ) );

			return;
		}

		printf( '<h2>%s</h2>', esc_html__( 'What this import will do', 'basic-firewall' ) );

		echo '<table class="widefat striped"><tbody>';

		foreach ( array(
			'rules_new'         => __( 'New rules', 'basic-firewall' ),
			'rules_overwritten' => __( 'Rules overwritten', 'basic-firewall' ),
			'rules_removed'     => __( 'Rules removed', 'basic-firewall' ),
			'sections_changed'  => __( 'Sections changed', 'basic-firewall' ),
		) as $key => $label ) {
			$values = (array) ( $preview['summary'][ $key ] ?? array() );

			printf(
				'<tr><th style="width:14rem">%s</th><td>%s</td></tr>',
				esc_html( $label ),
				array() === $values
					? '<em>' . esc_html__( 'none', 'basic-firewall' ) . '</em>'
					: esc_html( implode( ', ', array_map( 'strval', $values ) ) )
			);
		}

		echo '</tbody></table>';

		$this->open_form();

		printf( '<input type="hidden" name="import_action" value="apply" />' );
		printf( '<input type="hidden" name="mode" value="%s" />', esc_attr( $mode ) );

		submit_button( __( 'Apply this import', 'basic-firewall' ), 'primary', 'submit', false );

		printf(
			' <a href="%s" class="button">%s</a>',
			esc_url( \Kanopi\BasicFirewall\Admin\Admin::url( $this->slug() ) ),
			esc_html__( 'Cancel', 'basic-firewall' )
		);

		echo '</form>';
	}

	/**
	 * Re-render the paste form after a lost preview.
	 */
	private function render_form_again(): void {
		printf(
			'<p><a href="%s" class="button">%s</a></p>',
			esc_url( \Kanopi\BasicFirewall\Admin\Admin::url( $this->slug() ) ),
			esc_html__( 'Start again', 'basic-firewall' )
		);
	}
}
