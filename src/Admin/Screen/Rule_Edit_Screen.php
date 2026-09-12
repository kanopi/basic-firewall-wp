<?php
/**
 * Add or edit one rule.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Rule_Type;

/**
 * The rule form.
 *
 * Not reached from the menu -- it is always an operation on a rule, or on a
 * rule type chosen on the previous screen.
 */
final class Rule_Edit_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-rule';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return '' === $this->query( 'rule' )
			? __( 'Add a rule', 'basic-firewall' )
			: __( 'Edit rule', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function in_menu(): bool {
		return false;
	}

	/**
	 * The rule being edited, or a new one of the chosen type.
	 *
	 * @return array<string, mixed>|null
	 */
	private function current_rule(): ?array {
		$id = $this->query( 'rule' );

		if ( '' !== $id ) {
			foreach ( (array) $this->plugin()->settings()->get( 'rules', array() ) as $rule ) {
				if ( is_array( $rule ) && (string) ( $rule['id'] ?? '' ) === $id ) {
					return $rule;
				}
			}

			return null;
		}

		$type = $this->plugin()->rule_types()->get( $this->query( 'type' ) );

		if ( null === $type ) {
			return null;
		}

		return array(
			'id'                 => '',
			'type'               => $type->id(),
			'label'              => '',
			'enabled'            => true,
			'response'           => 'block',
			'weight'             => $type->weight(),
			'status_code'        => 0,
			'challenge_provider' => '',
			'expiration'         => 3600,
			'description'        => '',
			'settings'           => $type->default_settings(),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$existing = $this->current_rule();

		if ( null === $existing ) {
			return;
		}

		$type = $this->plugin()->rule_types()->get( (string) $existing['type'] );

		if ( null === $type ) {
			return;
		}

		$id = $this->posted( 'rule_id' );

		/*
		 * The identifier is what a log line names, what an import matches on and
		 * what an export addresses, so it has to be stable and machine-safe.
		 * Derived from the label when blank rather than rejected, because being
		 * made to invent a machine name is friction nobody wants on a form with
		 * an obvious answer available.
		 */
		$id = sanitize_key( '' !== $id ? $id : $this->posted( 'label' ) );

		$errors = array();

		if ( '' === $id ) {
			$errors['id'] = __( 'Give the rule a name. It is what the log will call it.', 'basic-firewall' );
		}

		if ( '' === $this->query( 'rule' ) && $this->id_exists( $id ) ) {
			$errors['id'] = __( 'A rule with that identifier already exists.', 'basic-firewall' );
		}

		$settings = $type->validate_settings( $this->posted_array( 'settings' ), $errors );

		$response   = $this->posted( 'response', 'block' );
		$expiration = (int) $this->posted( 'expiration', '3600' );

		$rule = array(
			'id'                 => $id,
			'type'               => $type->id(),
			'label'              => $this->posted( 'label' ),
			'enabled'            => '' !== $this->posted( 'enabled' ),
			'response'           => $response,
			'weight'             => (int) $this->posted( 'weight', '0' ),
			'status_code'        => (int) $this->posted( 'status_code', '0' ),
			'challenge_provider' => $this->posted( 'challenge_provider' ),
			'expiration'         => $expiration,
			'description'        => $this->posted_textarea( 'description' ),
			'settings'           => $settings,
		);

		if ( array() !== $errors ) {
			foreach ( $errors as $field => $message ) {
				Notices::add(
					sprintf( '<strong>%s</strong>: %s', esc_html( (string) $field ), esc_html( (string) $message ) ),
					'error'
				);
			}

			return;
		}

		$this->store( $rule );

		/*
		 * Zero means opposite things by response, so it is worth a word at the
		 * point it is saved rather than a discovery weeks later.
		 */
		if ( 'block' === $response && 0 === $expiration ) {
			Notices::add(
				__( 'This rule blocks matching clients <strong>permanently</strong>. A duration of 0 means "never expires", not "no limit" — they stay blocked until somebody clears them by hand.', 'basic-firewall' ),
				'warning'
			);
		}

		foreach ( $type->check_requirements( $settings ) as $problem ) {
			Notices::add( esc_html( $problem ), 'warning' );
		}

		Notices::add( __( 'Rule saved, and the firewall recompiled.', 'basic-firewall' ) );

		$this->redirect( 'basic-firewall-rules' );
	}

	/**
	 * Whether a rule identifier is taken.
	 *
	 * @param string $id Candidate identifier.
	 */
	private function id_exists( string $id ): bool {
		foreach ( (array) $this->plugin()->settings()->get( 'rules', array() ) as $rule ) {
			if ( is_array( $rule ) && (string) ( $rule['id'] ?? '' ) === $id ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Write the rule back.
	 *
	 * @param array<string, mixed> $rule The rule.
	 */
	private function store( array $rule ): void {
		$settings = $this->plugin()->settings();
		$rules    = (array) $settings->get( 'rules', array() );
		$editing  = $this->query( 'rule' );

		$replaced = false;

		foreach ( $rules as $index => $existing ) {
			if ( is_array( $existing ) && (string) ( $existing['id'] ?? '' ) === $editing ) {
				$rules[ $index ] = $rule;
				$replaced        = true;

				break;
			}
		}

		if ( ! $replaced ) {
			$rules[] = $rule;
		}

		$settings->set( 'rules', array_values( $rules ) );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$rule = $this->current_rule();

		if ( null === $rule ) {
			printf(
				'<p>%s</p><p><a href="%s" class="button">%s</a></p>',
				esc_html__( 'That rule does not exist, or its type is not registered on this site.', 'basic-firewall' ),
				esc_url( Admin::url( 'basic-firewall-rules' ) ),
				esc_html__( 'Back to the rule list', 'basic-firewall' )
			);

			return;
		}

		$type = $this->plugin()->rule_types()->get( (string) $rule['type'] );

		if ( null === $type ) {
			return;
		}

		printf(
			'<form method="post" action="%s">',
			esc_url(
				Admin::url(
					$this->slug(),
					array_filter(
						array(
							'rule' => $this->query( 'rule' ),
							'type' => $this->query( 'type' ),
						)
					)
				)
			)
		);

		$this->nonce_field();

		printf( '<h2>%s</h2>', esc_html( $type->label() ) );
		printf( '<p class="description" style="max-width:48rem">%s</p>', esc_html( $type->description() ) );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Name', 'basic-firewall' ),
			self::text( 'label', (string) $rule['label'] ),
			__( 'Shown in the rule list.', 'basic-firewall' )
		);

		$this->row(
			__( 'Identifier', 'basic-firewall' ),
			self::text( 'rule_id', (string) $rule['id'], 'text', '' === $this->query( 'rule' ) ? '' : 'readonly' ),
			__( 'What the log calls this rule, and what an import matches on. Left blank, it is derived from the name. It cannot be changed later without orphaning anything that refers to it.', 'basic-firewall' )
		);

		$this->row(
			__( 'Enabled', 'basic-firewall' ),
			self::checkbox( 'enabled', (bool) $rule['enabled'], __( 'Evaluate this rule', 'basic-firewall' ) )
		);

		$responses = array();

		foreach ( $type->allowed_responses() as $response ) {
			$responses[ $response ] = match ( $response ) {
				'allow'     => __( 'Allow — let the request through and stop evaluating', 'basic-firewall' ),
				'challenge' => __( 'Challenge — serve an interstitial the visitor must solve', 'basic-firewall' ),
				default     => __( 'Block — reject the request', 'basic-firewall' ),
			};
		}

		$this->row(
			__( 'Response', 'basic-firewall' ),
			self::select( 'response', $responses, (string) $rule['response'] ),
			__( 'Allow rules are evaluated first, then challenges, then blocks. A match ends evaluation, which is what makes a low-weight allow rule a reliable safety net.', 'basic-firewall' )
		);

		$this->row(
			__( 'Weight', 'basic-firewall' ),
			self::text( 'weight', (string) $rule['weight'], 'number', 'min="-1000" max="1000"' ),
			__( 'Lower runs first. Put cheap checks (address, path) ahead of expensive ones (Core Rule Set, vulnerability scoring) so obvious traffic is dealt with before anything costly runs.', 'basic-firewall' )
		);

		if ( $type->supports_shared_status_code() ) {
			$this->row(
				__( 'Status code', 'basic-firewall' ),
				self::text( 'status_code', (string) $rule['status_code'], 'number', 'min="0" max="599"' ),
				__( '0 uses the site-wide code from the General screen.', 'basic-firewall' )
			);
		}

		$this->row(
			'challenge' === $rule['response']
				? __( 'Re-challenge the visitor after', 'basic-firewall' )
				: __( 'Keep the client blocked for', 'basic-firewall' ),
			self::text( 'expiration', (string) $rule['expiration'], 'number', 'min="0"' ),
			'challenge' === $rule['response']
				? __( 'Seconds. A solved challenge issues a pass token with this lifetime; the next matching request after it expires is challenged afresh. <strong>0 falls back to 3600.</strong>', 'basic-firewall' )
				: __( 'Seconds. <strong>0 means permanently</strong> — matching clients stay blocked until somebody clears them by hand, which is not the same as "no limit".', 'basic-firewall' )
		);

		if ( 'challenge' === $rule['response'] ) {
			$providers = array( '' => __( 'Use the site default', 'basic-firewall' ) );

			foreach ( Library_Map::CHALLENGE_PROVIDERS as $key => $label ) {
				$providers[ $key ] = $label;
			}

			$this->row(
				__( 'Challenge provider', 'basic-firewall' ),
				self::select( 'challenge_provider', $providers, (string) $rule['challenge_provider'] ),
				__( 'Overrides the provider chosen on the Challenge screen, for this rule only.', 'basic-firewall' )
			);
		}

		$this->row(
			__( 'Notes', 'basic-firewall' ),
			self::textarea( 'description', (string) $rule['description'], 3 ),
			__( 'For whoever reads this rule next. Not used at runtime.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		printf( '<h2>%s</h2>', esc_html__( 'What this rule matches', 'basic-firewall' ) );

		$this->render_settings( $type, (array) $rule['settings'] );

		foreach ( $type->check_requirements( (array) $rule['settings'] ) as $problem ) {
			printf( '<div class="bfw-warning"><p>%s</p></div>', esc_html( $problem ) );
		}

		submit_button( __( 'Save rule', 'basic-firewall' ) );

		printf(
			'<a href="%s" class="button">%s</a>',
			esc_url( Admin::url( 'basic-firewall-rules' ) ),
			esc_html__( 'Cancel', 'basic-firewall' )
		);

		echo '</form>';
	}

	/**
	 * Render a rule type's own settings.
	 *
	 * @param Rule_Type            $type     The rule type.
	 * @param array<string, mixed> $settings Current settings.
	 */
	private function render_settings( Rule_Type $type, array $settings ): void {
		if ( $type instanceof Condition_Rule_Type_Base ) {
			$this->render_conditions( $type, $settings );

			return;
		}

		$this->render_generic_settings( $type, $settings );
	}

	/**
	 * The condition editor.
	 *
	 * @param Condition_Rule_Type_Base $type     The rule type.
	 * @param array<string, mixed>     $settings Current settings.
	 */
	private function render_conditions( Condition_Rule_Type_Base $type, array $settings ): void {
		$reflector = new \ReflectionMethod( $type, 'variable_options' );
		$reflector->setAccessible( true );

		/**
		 * The variables this rule type can read.
		 *
		 * @var array<string, string> $variables
		 */
		$variables = $reflector->invoke( $type );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Match', 'basic-firewall' ),
			self::select(
				'settings[match_type]',
				array(
					'any' => __( 'Any condition matches', 'basic-firewall' ),
					'all' => __( 'All conditions match', 'basic-firewall' ),
				),
				(string) ( $settings['match_type'] ?? 'any' )
			)
		);

		echo '</tbody></table>';

		$conditions = (array) ( $settings['conditions'] ?? array() );

		// Always offer three blank rows beyond what exists, so adding one needs
		// no JavaScript and the form degrades to something that still works.
		$rows = array_values( $conditions );

		for ( $i = 0; $i < 3; $i++ ) {
			$rows[] = array(
				'variable'       => '',
				'operator'       => 'equals',
				'value'          => '',
				'negate'         => false,
				'case_sensitive' => false,
			);
		}

		echo '<table class="widefat striped bfw-conditions"><thead><tr>';

		foreach ( array(
			__( 'Look at', 'basic-firewall' ),
			__( 'Comparison', 'basic-firewall' ),
			__( 'Value', 'basic-firewall' ),
			__( 'Options', 'basic-firewall' ),
		) as $heading ) {
			printf( '<th>%s</th>', esc_html( $heading ) );
		}

		echo '</tr></thead><tbody>';

		foreach ( $rows as $index => $condition ) {
			$name = sprintf( 'settings[conditions][%d]', $index );

			echo '<tr><td>';

			$options = array( '' => __( '— choose —', 'basic-firewall' ) );

			foreach ( $variables as $variable => $label ) {
				$options[ $variable ] = $variable;
			}

			$current = (string) ( $condition['variable'] ?? '' );

			// A free-form variable that is not in the list still has to render.
			if ( '' !== $current && ! isset( $options[ $current ] ) ) {
				$options[ $current ] = $current;
			}

			echo wp_kses( self::select( $name . '[variable]', $options, $current ), self::allowed_control_html() );

			if ( isset( $variables[ $current ] ) ) {
				printf( '<p class="description">%s</p>', esc_html( $variables[ $current ] ) );
			}

			echo '</td><td>';

			echo wp_kses(
				self::select(
					$name . '[operator]',
					Condition_Rule_Type_Base::OPERATORS,
					(string) ( $condition['operator'] ?? 'equals' )
				),
				self::allowed_control_html()
			);

			echo '</td><td>';

			echo wp_kses( self::text( $name . '[value]', (string) ( $condition['value'] ?? '' ) ), self::allowed_control_html() );

			echo '</td><td>';

			echo wp_kses( self::checkbox( $name . '[negate]', ! empty( $condition['negate'] ), __( 'Negate', 'basic-firewall' ) ), self::allowed_control_html() );

			echo '<br>';

			echo wp_kses( self::checkbox( $name . '[case_sensitive]', ! empty( $condition['case_sensitive'] ), __( 'Case sensitive', 'basic-firewall' ) ), self::allowed_control_html() );

			echo '</td></tr>';
		}

		echo '</tbody></table>';

		printf(
			'<p class="description">%s</p>',
			wp_kses_post(
				__( 'A regular expression <strong>must include its delimiters</strong> — <code>#^/wp-admin#</code>, not <code>^/wp-admin</code>. The firewall silently rejects an undelimited pattern, so the rule would save, report itself as active, and match nothing. Saving here checks for that.', 'basic-firewall' )
			)
		);

		if ( 'user_agent' === $type->id() ) {
			printf(
				'<div class="bfw-warning"><p>%s</p></div>',
				wp_kses_post(
					__( 'To stop scanners, use <code>automated</code> rather than <code>bot</code>. <code>bot</code> is backed by a curated crawler database that does not classify sqlmap, nikto, curl or python-requests — a rule written as <code>bot equals true</code> lets all four straight through. <code>automated</code> is that database plus a wider list.', 'basic-firewall' )
				)
			);
		}
	}

	/**
	 * A settings form for a rule type that is not condition-based.
	 *
	 * @param Rule_Type            $type     The rule type.
	 * @param array<string, mixed> $settings Current settings.
	 */
	private function render_generic_settings( Rule_Type $type, array $settings ): void {
		echo '<table class="form-table" role="presentation"><tbody>';

		foreach ( $type->default_settings() as $key => $default ) {
			$value  = $settings[ $key ] ?? $default;
			$name   = sprintf( 'settings[%s]', $key );
			$secret = in_array( (string) $key, $type->secret_settings(), true );

			if ( is_bool( $default ) ) {
				$this->row(
					$this->humanize( (string) $key ),
					self::checkbox( $name, (bool) $value, __( 'Enabled', 'basic-firewall' ) )
				);

				continue;
			}

			if ( is_array( $default ) ) {
				$this->row(
					$this->humanize( (string) $key ),
					self::textarea( $name, is_array( $value ) ? implode( "\n", array_map( 'strval', $value ) ) : (string) $value ),
					__( 'One per line.', 'basic-firewall' )
				);

				continue;
			}

			$description = '';

			if ( $secret ) {
				/*
				 * Warned at the point the key is typed, not in a readme. A
				 * literal key here is stored in the options table and travels in
				 * a database export; a token names a variable instead.
				 */
				/* translators: %s: the value described in the sentence. */
				$description = __( 'This is a credential. Prefer a token — <code>%env(MY_VARIABLE)%</code> — over the value itself: a token is exported and backed up safely, and a rotated value is picked up without a rebuild. Exports strip a literal value and say so.', 'basic-firewall' );
			}

			$this->row(
				$this->humanize( (string) $key ),
				self::text( $name, (string) $value, is_int( $default ) ? 'number' : 'text' ),
				$description
			);
		}

		echo '</tbody></table>';
	}

	/**
	 * Turn a settings key into a label.
	 *
	 * @param string $key Settings key.
	 */
	private function humanize( string $key ): string {
		return ucfirst( str_replace( '_', ' ', $key ) );
	}
}
