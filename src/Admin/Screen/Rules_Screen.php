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
use Kanopi\BasicFirewall\RuleType\Rule_Type;
use Kanopi\BasicFirewall\Transfer\Exporter;
use Kanopi\BasicFirewall\Transfer\Importer;

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

			return;
		}

		if ( 'import' === $action ) {
			$this->handle_import();
		}
	}

	/**
	 * Bring one exported rule back in.
	 *
	 * The counterpart to the export button, and it was missing: a rule could be
	 * sent out of a site and there was nowhere on this screen to send one back.
	 * The full Import screen would take the document -- it is an ordinary
	 * configuration document with one rule in it -- but only somebody who
	 * already knew that would find it, and "paste your rule into the screen
	 * labelled Import a configuration" reads like a way to overwrite the site.
	 *
	 * Always a merge, never a replace. A document arriving here holds one rule,
	 * and the mode that empties every other section is not a thing anyone
	 * reaches for from a list of rules.
	 */
	private function handle_import(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$yaml = $this->uploaded_document();

		if ( '' === trim( $yaml ) ) {
			$yaml = $this->posted_textarea( 'document' );
		}

		if ( '' === trim( $yaml ) ) {
			Notices::add( __( 'Paste a rule, or choose a file to upload.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		$importer = new Importer();
		$preview  = $importer->preview( $yaml, 'merge' );

		if ( ! $preview['ok'] ) {
			Notices::add(
				sprintf(
					/* translators: %s: the parser's complaint. */
					__( 'That document could not be read, so nothing was imported: %s', 'basic-firewall' ),
					esc_html( (string) $preview['error'] )
				),
				'error'
			);

			$this->redirect( $this->slug() );
		}

		$summary = (array) $preview['summary'];
		$new     = (array) ( $summary['rules_new'] ?? array() );
		$changed = (array) ( $summary['rules_overwritten'] ?? array() );

		if ( array() === $new && array() === $changed ) {
			Notices::add(
				__( 'That document contains no rules. Use the Import screen for a whole configuration.', 'basic-firewall' ),
				'error'
			);

			$this->redirect( $this->slug() );
		}

		$result = $importer->import( $yaml, 'merge' );

		foreach ( $result['problems'] as $problem ) {
			Notices::add(
				sprintf( '<strong>%s</strong>: %s', esc_html( (string) $problem['path'] ), esc_html( (string) $problem['message'] ) ),
				'warning'
			);
		}

		if ( ! $result['ok'] ) {
			Notices::add(
				sprintf(
					/* translators: %s: the reason. */
					__( 'Nothing was imported: %s', 'basic-firewall' ),
					esc_html( (string) $result['error'] )
				),
				'error'
			);

			$this->redirect( $this->slug() );
		}

		/*
		 * Both counts are reported, and overwriting is named rather than
		 * folded into a total. Importing a rule whose identifier a site already
		 * uses replaces that rule, and somebody who meant to add one needs to
		 * be told that is not what happened.
		 */
		Notices::add(
			sprintf(
				/* translators: 1: comma-separated new rule ids, 2: comma-separated replaced rule ids. */
				__( 'Imported. Added: %1$s. Replaced: %2$s.', 'basic-firewall' ),
				array() === $new ? __( 'nothing', 'basic-firewall' ) : esc_html( implode( ', ', array_map( 'strval', $new ) ) ),
				array() === $changed ? __( 'nothing', 'basic-firewall' ) : esc_html( implode( ', ', array_map( 'strval', $changed ) ) )
			)
		);

		$this->redirect( $this->slug() );
	}

	/**
	 * The uploaded file's contents, or an empty string.
	 *
	 * Read from the temporary upload rather than moved into the site: the
	 * document is parsed and thrown away, and a configuration file left in
	 * the uploads directory would be readable over the web.
	 */
	private function uploaded_document(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- verify() ran in handle_import() before this was called.
		$upload = isset( $_FILES['document']['tmp_name'] ) ? sanitize_text_field( wp_unslash( (string) $_FILES['document']['tmp_name'] ) ) : '';

		/*
		 * is_uploaded_file() is the check that matters, and it is not
		 * interchangeable with checking the path looks reasonable: it asks PHP
		 * whether this exact path came from this request's upload, which is
		 * what stops a crafted field naming a file already on disk and having
		 * the importer read it back to us.
		 */
		if ( '' === $upload || ! is_uploaded_file( $upload ) ) {
			return '';
		}

		$contents = file_get_contents( $upload ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local temporary file this request just created, not a remote URL.

		return false === $contents ? '' : $contents;
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
		$this->render_import();
	}

	/**
	 * Bring a rule in from a file or the clipboard.
	 *
	 * Below the table and folded away, because it is the rarer half of a pair:
	 * the export button sits on every row, and this is where what comes out of
	 * one site goes back into another.
	 */
	private function render_import(): void {
		if ( ! Admin::can_manage() ) {
			return;
		}

		printf(
			'<details class="bfw-import"><summary>%s</summary>',
			esc_html__( 'Import a rule', 'basic-firewall' )
		);

		printf(
			'<p>%s</p>',
			esc_html__( 'Paste a rule exported from this or another site, or upload the file. It is merged into the rules below: a rule whose identifier is already in use here is replaced, and every other rule and setting is left alone.', 'basic-firewall' )
		);

		printf(
			'<form method="post" enctype="multipart/form-data" action="%s">',
			esc_url( Admin::url( $this->slug(), array( 'action' => 'import' ) ) )
		);

		$this->nonce_field();

		printf(
			'<p><input type="file" name="document" accept=".yml,.yaml,text/yaml,text/plain" /></p><p>%s</p>',
			esc_html__( 'or paste it:', 'basic-firewall' )
		);

		printf(
			'<p><textarea name="document" rows="8" class="large-text code" data-bfw-yaml="1" placeholder="%s"></textarea></p>',
			esc_attr__( "version: 1\nrules:\n  - id: my-rule\n    type: ip_address\n    ...", 'basic-firewall' )
		);

		printf(
			'<p>%s</p>',
			wp_kses_post(
				__( 'An export has its credentials stripped, so a rule that needed one — a reputation API key, a list behind a token — arrives without it and keeps whatever this site already had under that identifier. Nothing is overwritten with a blank.', 'basic-firewall' )
			)
		);

		submit_button( __( 'Import rule', 'basic-firewall' ), 'secondary' );

		echo '</form></details>';
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

		echo '<table class="widefat striped bfw-rules"><thead><tr>';

		/*
		 * Keyed by column rather than positional, following the `column-*`
		 * convention WordPress uses on its own list tables. The stylesheet
		 * needs to reach the type column to stop it wrapping, and nth-child
		 * would have tied that to the order the columns happen to be in today.
		 */
		foreach ( array(
			'rule'     => __( 'Rule', 'basic-firewall' ),
			'type'     => __( 'Type', 'basic-firewall' ),
			'response' => __( 'Response', 'basic-firewall' ),
			'weight'   => __( 'Weight', 'basic-firewall' ),
			'summary'  => __( 'Summary', 'basic-firewall' ),
			'actions'  => __( 'Actions', 'basic-firewall' ),
		) as $column => $heading ) {
			printf( '<th class="column-%s">%s</th>', esc_attr( $column ), esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $rules as $rule ) {
			$id   = (string) ( $rule['id'] ?? '' );
			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			echo '<tr>';

			printf(
				'<td class="column-rule"><strong>%s</strong>%s<br><code>%s</code></td>',
				esc_html( (string) ( $rule['label'] ?? $id ) ),
				empty( $rule['enabled'] ) ? ' <em>(' . esc_html__( 'disabled', 'basic-firewall' ) . ')</em>' : '',
				esc_html( $id )
			);

			if ( null === $type ) {
				printf(
					'<td class="column-type"><span>%s</span><br><code>%s</code></td>',
					esc_html__( 'Unknown type', 'basic-firewall' ),
					esc_html( (string) ( $rule['type'] ?? '' ) )
				);
			} elseif ( ! $type->is_available() ) {
				printf(
					'<td class="column-type">%s<br><span>%s</span></td>',
					esc_html( $type->label() ),
					esc_html__( 'Not available — this rule is skipped', 'basic-firewall' )
				);
			} else {
				printf( '<td class="column-type">%s</td>', esc_html( $type->label() ) );
			}

			printf( '<td class="column-response">%s</td>', esc_html( (string) ( $rule['response'] ?? '' ) ) );
			printf( '<td class="column-weight">%d</td>', (int) ( $rule['weight'] ?? 0 ) );

			printf( '<td class="column-summary">%s</td>', esc_html( $this->summarize( $type, (array) ( $rule['settings'] ?? array() ) ) ) );

			echo '<td class="column-actions">';

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

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			esc_html__( 'Listed in the order they are evaluated in, cheapest first. A rule type contributed by another plugin appears here alongside the shipped ones.', 'basic-firewall' )
		);

		echo '<table class="widefat striped bfw-rule-types"><thead><tr>';

		foreach ( array(
			__( 'Rule type', 'basic-firewall' ),
			__( 'Matches on', 'basic-firewall' ),
			__( 'Source', 'basic-firewall' ),
			'',
		) as $heading ) {
			printf( '<th>%s</th>', esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		$shipped = $this->plugin()->rule_types()->shipped_ids();

		foreach ( $this->plugin()->rule_types()->all() as $type ) {
			$available = $type->is_available();

			echo '<tr>';

			printf(
				'<td><strong>%s</strong><br><code>%s</code></td>',
				esc_html( $type->label() ),
				esc_html( $type->id() )
			);

			printf( '<td>%s</td>', esc_html( $type->description() ) );

			/*
			 * Named rather than implied. A rule type this plugin did not ship
			 * compiles into the same firewall as one it did, so somebody
			 * deciding whether to trust it should not have to work out where it
			 * came from.
			 */
			printf(
				'<td>%s</td>',
				in_array( $type->id(), $shipped, true )
					? esc_html__( 'Built in', 'basic-firewall' )
					: '<em>' . esc_html__( 'Added by another plugin', 'basic-firewall' ) . '</em>'
			);

			printf(
				'<td>%s</td>',
				$available
					? sprintf(
						'<a href="%s" class="button">%s</a>',
						esc_url( Admin::url( 'basic-firewall-rule', array( 'type' => $type->id() ) ) ),
						esc_html__( 'Add', 'basic-firewall' )
					)
					: sprintf(
						'<span class="bfw-unavailable">%s</span>',
						esc_html__( 'The installed firewall library cannot provide this.', 'basic-firewall' )
					)
			);

			echo '</tr>';
		}

		echo '</tbody></table>';

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

	/**
	 * One rule's summary, or a note that it could not be read.
	 *
	 * Wrapped because this is a listing, and a listing is the one screen that
	 * has to survive bad data: a rule whose settings are in a shape its type
	 * did not expect used to throw here, and the throw took the whole Rules
	 * screen with it -- so the page you would go to in order to find and fix
	 * the rule was the page that would not load.
	 *
	 * Settings reach this method from an imported document as readily as from
	 * the rule form, and only the form validates them, so "a shape the type did
	 * not expect" is a supported route rather than a hypothetical one.
	 *
	 * @param Rule_Type|null       $type     The rule type, or null when unknown.
	 * @param array<string, mixed> $settings The rule's settings.
	 */
	private function summarize( ?Rule_Type $type, array $settings ): string {
		if ( null === $type ) {
			return '';
		}

		try {
			$summary = $type->summarize( $settings );
		} catch ( \Throwable $e ) {
			return __( 'These settings could not be read. Open the rule to repair it.', 'basic-firewall' );
		}

		return implode( ' ', array_map( 'strval', array_slice( $summary, 0, 3 ) ) );
	}
}
