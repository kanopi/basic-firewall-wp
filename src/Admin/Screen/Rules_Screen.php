<?php
/**
 * The rule collection.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Transfer\Exporter;

/**
 * Lists the rules, and the rule-type chooser for adding one.
 */
final class Rules_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-rules';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Firewall rules', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'Rules', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return esc_html__( 'Rules are evaluated in weight order, lowest first. Allow rules run before challenges, and challenges before blocks — a match ends evaluation, which is what makes a low-weight allow rule for your own address a reliable safety net.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		$action = $this->query( 'action' );

		if ( 'delete' === $action ) {
			$this->handle_delete();

			return;
		}

		if ( 'export' === $action ) {
			$this->handle_export();
		}
	}

	/**
	 * Delete a rule, once it has been confirmed.
	 */
	private function handle_delete(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$id       = $this->posted( 'rule_id' );
		$settings = $this->plugin()->settings();
		$rules    = (array) $settings->get( 'rules', array() );

		$remaining = array_values(
			array_filter(
				$rules,
				static fn ( $rule ): bool => ! is_array( $rule ) || (string) ( $rule['id'] ?? '' ) !== $id
			)
		);

		if ( count( $remaining ) === count( $rules ) ) {
			Notices::add( __( 'That rule no longer exists.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		$settings->set( 'rules', $remaining );

		/* translators: %s: rule identifier. */
		Notices::add( sprintf( __( 'Rule "%s" deleted, and the firewall recompiled.', 'basic-firewall' ), $id ) );

		$this->redirect( $this->slug() );
	}

	/**
	 * Send one rule as a download.
	 */
	private function handle_export(): void {
		$id = $this->query( 'rule' );

		if ( ! wp_verify_nonce( $this->query( '_wpnonce' ), 'basic_firewall_export_rule_' . $id ) ) {
			return;
		}

		$yaml = ( new Exporter() )->rule_to_yaml( $id );

		if ( null === $yaml ) {
			Notices::add( __( 'That rule no longer exists.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		header( 'Content-Type: text/yaml; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="firewall-rule-' . sanitize_file_name( $id ) . '.yml"' );

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo $yaml;

		exit;
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$confirming = $this->query( 'action' );

		if ( 'delete' === $confirming ) {
			$this->render_delete_confirmation();

			return;
		}

		if ( 'add' === $confirming ) {
			$this->render_type_chooser();

			return;
		}

		printf(
			'<p><a href="%s" class="button button-primary">%s</a></p>',
			esc_url( Admin::url( $this->slug(), array( 'action' => 'add' ) ) ),
			esc_html__( 'Add a rule', 'basic-firewall' )
		);

		$this->render_table();
	}

	/**
	 * The rule listing.
	 */
	private function render_table(): void {
		$rules    = (array) $this->plugin()->settings()->get( 'rules', array() );
		$registry = $this->plugin()->rule_types();

		if ( array() === $rules ) {
			printf(
				'<p>%s</p>',
				esc_html__( 'No rules yet. The firewall is evaluating nothing, which is how it ships — add your own address as an Allow rule first, then the rules you actually want.', 'basic-firewall' )
			);

			return;
		}

		usort(
			$rules,
			static fn ( array $a, array $b ): int => ( (int) ( $a['weight'] ?? 0 ) ) <=> ( (int) ( $b['weight'] ?? 0 ) )
		);

		echo '<table class="widefat striped"><thead><tr>';

		foreach ( array(
			__( 'Rule', 'basic-firewall' ),
			__( 'Type', 'basic-firewall' ),
			__( 'Response', 'basic-firewall' ),
			__( 'Weight', 'basic-firewall' ),
			__( 'Summary', 'basic-firewall' ),
			__( 'Actions', 'basic-firewall' ),
		) as $heading ) {
			printf( '<th>%s</th>', esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $rules as $rule ) {
			$id   = (string) ( $rule['id'] ?? '' );
			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			echo '<tr>';

			printf(
				'<td><strong>%s</strong>%s<br><code>%s</code></td>',
				esc_html( (string) ( $rule['label'] ?? $id ) ),
				empty( $rule['enabled'] ) ? ' <em>(' . esc_html__( 'disabled', 'basic-firewall' ) . ')</em>' : '',
				esc_html( $id )
			);

			if ( null === $type ) {
				printf(
					'<td><span style="color:#d63638">%s</span><br><code>%s</code></td>',
					esc_html__( 'Unknown type', 'basic-firewall' ),
					esc_html( (string) ( $rule['type'] ?? '' ) )
				);
			} elseif ( ! $type->is_available() ) {
				printf(
					'<td>%s<br><span style="color:#d63638">%s</span></td>',
					esc_html( $type->label() ),
					esc_html__( 'Not available — this rule is skipped', 'basic-firewall' )
				);
			} else {
				printf( '<td>%s</td>', esc_html( $type->label() ) );
			}

			printf( '<td>%s</td>', esc_html( (string) ( $rule['response'] ?? '' ) ) );
			printf( '<td>%d</td>', (int) ( $rule['weight'] ?? 0 ) );

			$summary = null === $type ? array() : $type->summarize( (array) ( $rule['settings'] ?? array() ) );

			printf(
				'<td>%s</td>',
				esc_html( implode( ' ', array_map( 'strval', array_slice( $summary, 0, 3 ) ) ) )
			);

			echo '<td>';

			printf(
				'<a href="%s">%s</a> | ',
				esc_url( Admin::url( 'basic-firewall-rule', array( 'rule' => $id ) ) ),
				esc_html__( 'Edit', 'basic-firewall' )
			);

			/*
			 * Export is offered even for a rule whose type this site cannot
			 * render -- that is exactly the rule somebody wants to hand to a
			 * site that can.
			 */
			printf(
				'<a href="%s">%s</a> | ',
				esc_url(
					wp_nonce_url(
						Admin::url(
							$this->slug(),
							array(
								'action' => 'export',
								'rule'   => $id,
							)
						),
						'basic_firewall_export_rule_' . $id
					)
				),
				esc_html__( 'Export', 'basic-firewall' )
			);

			printf(
				'<a href="%s" style="color:#b32d2e">%s</a>',
				esc_url(
					Admin::url(
						$this->slug(),
						array(
							'action' => 'delete',
							'rule'   => $id,
						)
					)
				),
				esc_html__( 'Delete', 'basic-firewall' )
			);

			echo '</td></tr>';
		}

		echo '</tbody></table>';
	}

	/**
	 * The rule-type chooser.
	 */
	private function render_type_chooser(): void {
		printf( '<h2>%s</h2>', esc_html__( 'Choose a rule type', 'basic-firewall' ) );

		echo '<div class="bfw-cards">';

		foreach ( $this->plugin()->rule_types()->all() as $type ) {
			$available = $type->is_available();

			printf(
				'<div class="bfw-card bfw-card--%s"><h2>%s</h2><p>%s</p><p>%s</p></div>',
				$available ? 'good' : 'recommended',
				esc_html( $type->label() ),
				esc_html( $type->description() ),
				$available
					? sprintf(
						'<a href="%s" class="button">%s</a>',
						esc_url( Admin::url( 'basic-firewall-rule', array( 'type' => $type->id() ) ) ),
						esc_html__( 'Add this rule', 'basic-firewall' )
					)
					: '<em>' . esc_html__( 'The installed library cannot provide this rule type.', 'basic-firewall' ) . '</em>'
			);
		}

		echo '</div>';

		printf(
			'<p><a href="%s">%s</a></p>',
			esc_url( Admin::url( $this->slug() ) ),
			esc_html__( 'Back to the rule list', 'basic-firewall' )
		);
	}

	/**
	 * Confirm a deletion.
	 */
	private function render_delete_confirmation(): void {
		$id = $this->query( 'rule' );

		printf( '<h2>%s</h2>', esc_html__( 'Delete this rule?', 'basic-firewall' ) );

		printf(
			'<p>%s</p>',
			sprintf(
				/* translators: %s: rule identifier. */
				esc_html__( 'Rule "%s" will be removed and the firewall recompiled. This cannot be undone, though an export taken beforehand can be imported back.', 'basic-firewall' ),
				esc_html( $id )
			)
		);

		printf( '<form method="post" action="%s">', esc_url( Admin::url( $this->slug(), array( 'action' => 'delete' ) ) ) );

		$this->nonce_field();

		printf( '<input type="hidden" name="rule_id" value="%s" />', esc_attr( $id ) );

		submit_button( __( 'Delete the rule', 'basic-firewall' ), 'delete', 'submit', false );

		printf(
			' <a href="%s" class="button">%s</a>',
			esc_url( Admin::url( $this->slug() ) ),
			esc_html__( 'Cancel', 'basic-firewall' )
		);

		echo '</form>';
	}
}
