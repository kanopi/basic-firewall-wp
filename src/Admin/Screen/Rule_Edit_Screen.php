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
use Kanopi\BasicFirewall\RuleType\Response_Settings;
use Kanopi\BasicFirewall\RuleType\Rule_Type;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;
use Kanopi\BasicFirewall\Transfer\Secret_Paths;
use Kanopi\Firewall\Utility\Schedule;
use Symfony\Component\Yaml\Yaml;

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
			'observe'            => false,
			'response'           => 'block',
			'weight'             => $type->weight(),
			'status_code'        => 0,
			'challenge_provider' => '',
			'record'             => 'default',
			'redirect_to'        => '',
			'redirect_status'    => 302,
			'mark_as'            => '',
			'mark_header'        => '',
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

		$settings = $type->validate_settings( $this->with_secret_fields( $type, $this->posted_array( 'settings' ), (array) ( $existing['settings'] ?? array() ) ), $errors );

		$response   = $this->posted( 'response', 'block' );
		$expiration = (int) $this->posted( 'expiration', '3600' );

		$schedule = array(
			'timezone' => $this->posted( 'schedule_timezone' ),
			'days'     => $this->posted_array( 'schedule_days' ),
			'hours'    => $this->posted( 'schedule_hours' ),
			'from'     => $this->posted( 'schedule_from' ),
			'until'    => $this->posted( 'schedule_until' ),
		);

		/*
		 * Where the window is not offered, the stored one is kept rather than
		 * read as blank. Clearing it on an unrelated edit would turn an
		 * after-hours rule into an all-hours one without anybody choosing that.
		 */
		$windows = ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_rule_schedule();

		if ( ! $windows ) {
			$schedule = (array) ( $existing['schedule'] ?? array() );
		}

		/*
		 * Validated by the library rather than here.
		 *
		 * `Schedule::fromMetadata()` is what will read this at runtime, and it
		 * throws with a message naming what it did not understand -- a timezone
		 * that is not a zone, an hours range that is not a range. Re-deriving
		 * those rules in this plugin would be two implementations that agree
		 * until they do not, and the one that matters is the library's.
		 */
		$declaration = Rule_Type_Base::schedule_declaration( $schedule );

		if ( $windows && array() !== $declaration ) {
			try {
				Schedule::fromMetadata( $declaration );
			} catch ( \Throwable $e ) {
				$errors['schedule'] = sprintf(
					/* translators: %s: the library's complaint. */
					__( 'That schedule could not be read, so the rule was not saved: %s', 'basic-firewall' ),
					$e->getMessage()
				);
			}
		}

		/*
		 * Stored only for the response that reads them. Every row is now on the
		 * page whatever the response, so without this a rule switched from
		 * redirect to block would keep a destination nothing acts on -- and
		 * would still be refused over a blank one.
		 */
		$redirect_to = 'redirect' === $response ? trim( $this->posted( 'redirect_to' ) ) : '';
		$mark_as     = 'mark' === $response ? trim( $this->posted( 'mark_as' ) ) : '';
		$mark_header = 'mark' === $response ? trim( $this->posted( 'mark_header' ) ) : '';

		if ( 'redirect' === $response ) {
			$problem = $this->redirect_problem( $redirect_to );

			if ( null !== $problem ) {
				$errors['redirect_to'] = $problem;
			}
		}

		if ( 'mark' === $response && ! Response_Settings::is_mark_name( $mark_as ) ) {
			$errors['mark_as'] = __( 'Use letters, numbers, hyphens and underscores only. The name becomes part of the request attribute "firewall.mark.NAME", which your code has to be able to address.', 'basic-firewall' );
		}

		if ( 'mark' === $response && ! Response_Settings::is_header_name( $mark_header ) ) {
			$errors['mark_header'] = __( 'A header name can contain letters, numbers and hyphens only.', 'basic-firewall' );
		}

		/*
		 * A redirect answers with a status of its own and a mark never answers
		 * at all, so for both of them -- as for allow -- the shared status code
		 * can only ever be a value that does nothing.
		 */
		$status_code = in_array( $response, array( 'allow', 'redirect', 'mark' ), true )
			? 0
			: (int) $this->posted( 'status_code', '0' );

		/*
		 * Not conditioned on the response: observing is orthogonal to what the
		 * rule would otherwise do. Where the box is not offered, the stored
		 * value is kept rather than read as unticked -- an edit on a library
		 * without observe mode must not quietly turn a watching rule into an
		 * enforcing one.
		 */
		$observe = ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_observe_mode()
			? '' !== $this->posted( 'observe' )
			: ! empty( $existing['observe'] );

		$rule = array(
			'id'                 => $id,
			'type'               => $type->id(),
			'label'              => $this->posted( 'label' ),
			'enabled'            => '' !== $this->posted( 'enabled' ),
			'observe'            => $observe,
			'response'           => $response,
			'weight'             => (int) $this->posted( 'weight', '0' ),
			'status_code'        => $status_code,
			'challenge_provider' => 'challenge' === $response ? $this->posted( 'challenge_provider' ) : '',
			'record'             => $this->posted( 'record', 'default' ),
			'schedule'           => $schedule,
			'redirect_to'        => $redirect_to,
			'redirect_status'    => 'redirect' === $response ? (int) $this->posted( 'redirect_status', '302' ) : 302,
			'mark_as'            => $mark_as,
			'mark_header'        => $mark_header,
			'expiration'         => $expiration,
			'description'        => $this->posted_textarea( 'description' ),
			'settings'           => $settings,
		);

		if ( array() !== $errors ) {
			foreach ( $errors as $field => $message ) {
				Notices::add(
					sprintf( '<strong>%s</strong>: %s', esc_html( $this->field_label( (string) $field ) ), esc_html( (string) $message ) ),
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

		/*
		 * Said at the point it is saved, because the library will not say it
		 * at all: it clamps and serves.
		 *
		 * `challenge.ttl` is a ceiling as well as a default, so a rule asking
		 * for longer is granted the ceiling instead -- which looks exactly like
		 * the rule's own setting being ignored, and is the sort of thing found
		 * weeks later by wondering why people are being re-challenged.
		 */
		$ceiling = (int) $this->plugin()->settings()->get( 'challenge.ttl', 3600 );

		if ( 'challenge' === $response && $expiration > $ceiling ) {
			Notices::add(
				sprintf(
					/* translators: 1: requested seconds, 2: the ceiling in seconds. */
					__( 'This rule asks for a %1$d second pass and will get %2$d. The site-wide ceiling on the Challenge screen is what decides it, and raising that raises it for every challenge rule.', 'basic-firewall' ),
					$expiration,
					$ceiling
				),
				'warning'
			);
		}

		/*
		 * A warning rather than a refusal: only the obvious shapes are checked,
		 * and a rule can redirect somewhere it also matches when an allow rule
		 * lets that request through first.
		 */
		if ( 'redirect' === $response && 'url' === $type->id() && Response_Settings::redirect_loops( $redirect_to, (array) ( $settings['conditions'] ?? array() ) ) ) {
			Notices::add(
				sprintf(
					/* translators: %s: the redirect destination. */
					__( 'This rule may match the page it redirects to, which would send the visitor round in a loop. Check that %s is not matched by this rule\'s own conditions.', 'basic-firewall' ),
					'<code>' . esc_html( $redirect_to ) . '</code>'
				),
				'warning'
			);
		}

		if ( 'rate_limit' === $type->id() ) {
			$this->warn_about_rate_limit_keys( $rule );
		}

		foreach ( $type->check_requirements( $settings ) as $problem ) {
			Notices::add( esc_html( $problem ), 'warning' );
		}

		Notices::add( __( 'Rule saved, and the firewall recompiled.', 'basic-firewall' ) );

		$this->redirect( 'basic-firewall-rules' );
	}

	/**
	 * Put the credential fields into what was posted, the way a password field works.
	 *
	 * A field a type describes as `secret` is never rendered with its value,
	 * so a blank one on the way back means "keep what is stored", not "clear
	 * it"; the box beside it is how it is cleared. And it is read from the
	 * request as typed rather than through the textarea sanitiser, which
	 * trims, strips anything tag-shaped and drops percent-encoded octets --
	 * each of which turns a working password into one that fails to
	 * authenticate, with nothing on the screen to say why.
	 *
	 * @param Rule_Type            $type   The rule type.
	 * @param array<string, mixed> $posted The sanitised settings as posted.
	 * @param array<string, mixed> $stored The settings stored before this save.
	 *
	 * @return array<string, mixed>
	 */
	private function with_secret_fields( Rule_Type $type, array $posted, array $stored ): array {
		$clear = $this->posted_array( 'clear_secret' );

		foreach ( self::secret_fields( $type ) as $path => $segments ) {
			$typed = self::raw_posted( array_merge( array( 'settings' ), $segments ) );

			if ( ! Secret_Paths::is_empty( Secret_Paths::get( $clear, $path ) ) ) {
				$value = '';
			} elseif ( null === $typed || '' === $typed ) {
				$value = (string) ( Secret_Paths::get( $stored, $path ) ?? '' );
			} else {
				$value = $typed;
			}

			Secret_Paths::set( $posted, $path, $value );
		}

		return $posted;
	}

	/**
	 * The settings a type describes as credentials to be typed but never shown.
	 *
	 * @param Rule_Type $type The rule type.
	 *
	 * @return array<string, list<string>> Dotted path => its segments.
	 */
	private static function secret_fields( Rule_Type $type ): array {
		$found = array();

		foreach ( $type->settings_help() as $key => $field ) {
			if ( ! is_array( $field ) ) {
				continue;
			}

			if ( ! empty( $field['secret'] ) ) {
				$found[ (string) $key ] = array( (string) $key );
			}

			foreach ( (array) ( $field['fields'] ?? array() ) as $child => $child_field ) {
				if ( is_array( $child_field ) && ! empty( $child_field['secret'] ) ) {
					$found[ $key . '.' . $child ] = array( (string) $key, (string) $child );
				}
			}
		}

		return $found;
	}

	/**
	 * A posted string exactly as typed, or null when it was not posted.
	 *
	 * @param list<string> $segments Where it is in the request, outermost first.
	 */
	private static function raw_posted( array $segments ): ?string {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- handle() verified the nonce before calling this.
		$node = $_POST;

		foreach ( $segments as $segment ) {
			if ( ! is_array( $node ) || ! isset( $node[ $segment ] ) ) {
				return null;
			}

			$node = $node[ $segment ];
		}

		// A credential is used as typed and never printed; sanitising it would change it.
		return is_string( $node ) ? (string) wp_unslash( $node ) : null;
	}

	/**
	 * Say what an identity-keyed rate limit does not do, at the moment it is saved.
	 *
	 * As well as in Site Health, because this is the moment the choice is made
	 * and an identity-keyed limit reads as a tightening while being half of
	 * one. It catches a botnet against one account and misses one client
	 * walking a list of accounts, and it records no offense -- so on its own it
	 * leaves brute force unprotected and the block list empty.
	 *
	 * A warning, not a refusal: an address limit can legitimately live in
	 * front of WordPress entirely, where nothing here can see it.
	 *
	 * @param array<string, mixed> $rule The rule just saved.
	 */
	private function warn_about_rate_limit_keys( array $rule ): void {
		$unpaired = Rate_Limit::unpaired_identity_limits( (array) $this->plugin()->settings()->get( 'rules', array() ) );
		$patterns = $unpaired[ (string) $rule['id'] ] ?? array();

		if ( array() !== $patterns ) {
			Notices::add(
				sprintf(
					/* translators: %s: comma-separated patterns. */
					__( 'The limit on %s counts something other than the client address, and no other rate limit rule counts the address on that pattern. It will refuse requests but never ban anyone, and it misses one client working through a list of accounts — each name gets a fresh allowance. Add a separate rate limit rule on the same pattern that counts the address, usually with a looser allowance.', 'basic-firewall' ),
					'<code>' . esc_html( implode( ', ', $patterns ) ) . '</code>'
				),
				'warning'
			);
		}

		/*
		 * Recording an identity-keyed limit hands the ban to whichever address
		 * happened to trip it -- which, once an attacker has spent an account's
		 * budget, is the account owner's own next login. The library withholds
		 * that by default for exactly this reason; `record: true` overrides it.
		 */
		$identity = array_filter(
			Rate_Limit::limits( (array) $rule['settings'] ),
			static fn ( array $limit ): bool => Rate_Limit::counts_an_identity( $limit['key'] )
		);

		if ( 'yes' === ( $rule['record'] ?? 'default' ) && array() !== $identity ) {
			Notices::add(
				__( 'This rule records the client, and some of its limits count an account rather than the address. An attacker can spend a victim\'s allowance from their own machines, and the victim\'s next attempt would then put the <strong>victim\'s</strong> address on the block list — for everything, lengthening each time if escalation is on. Leave Record the client on Default unless the account and the address really are the same thing.', 'basic-firewall' ),
				'warning'
			);
		}
	}

	/**
	 * Why a redirect destination cannot be saved, in words, or null.
	 *
	 * The destination is not optional in the way an empty field usually is:
	 * see Response_Settings::redirect_problem() for what the library does with
	 * a redirect rule naming nowhere.
	 *
	 * @param string $location The destination as typed.
	 */
	private function redirect_problem( string $location ): ?string {
		return match ( Response_Settings::redirect_problem( $location ) ) {
			Response_Settings::REDIRECT_EMPTY       => __( 'A redirect rule needs somewhere to send the visitor. Without it, every request the rule matches becomes a firewall error instead of a redirect — and is then served as though the rule did not exist.', 'basic-firewall' ),
			Response_Settings::REDIRECT_OFF_SITE    => __( 'A destination starting with "//" sends the visitor to another site. Write a path beginning with a single "/", or a full URL including "https://".', 'basic-firewall' ),
			Response_Settings::REDIRECT_UNSUPPORTED => __( 'Write a path beginning with "/", or a full URL beginning with "http://" or "https://".', 'basic-firewall' ),
			default                                 => null,
		};
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

		/*
		 * Offered only where the library honours it. A box that said "observe"
		 * over a library ignoring the key would enforce on live traffic while
		 * claiming to watch, which is the one way this must never be wrong.
		 */
		if ( ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_observe_mode() ) {
			$this->row(
				__( 'Observe only', 'basic-firewall' ),
				self::checkbox( 'observe', ! empty( $rule['observe'] ), __( 'Match and log, but do not act', 'basic-firewall' ) ),
				__( 'The rule is evaluated and every match is logged at warning level, then treated as no match — evaluation carries on and every other rule enforces as normal. This is how you find out what a rule <em>would</em> have done before letting it do it: add it, leave it a week, count its matches on the <strong>Log</strong> screen with <em>Observed only</em>, then clear this box.', 'basic-firewall' )
			);
		}

		$responses = array();

		foreach ( $type->allowed_responses() as $response ) {
			$responses[ $response ] = match ( $response ) {
				'allow'     => __( 'Allow — let the request through and stop evaluating', 'basic-firewall' ),
				'challenge' => __( 'Challenge — serve an interstitial the visitor must solve', 'basic-firewall' ),
				'redirect'  => __( 'Redirect — send the visitor somewhere else', 'basic-firewall' ),
				'mark'      => __( 'Mark — let the request through, but flag it', 'basic-firewall' ),
				'record'    => __( 'Record — let the request through, and block them next time', 'basic-firewall' ),
				default     => __( 'Block — reject the request', 'basic-firewall' ),
			};
		}

		$this->row(
			__( 'Response', 'basic-firewall' ),
			self::select( 'response', $responses, (string) $rule['response'] ),
			__( 'Evaluated in this order: allow, mark, record, challenge, redirect, block. An allow match ends evaluation immediately, which is what makes a low-weight allow rule a reliable safety net. Mark and record do not end it — they run even on a request something below is about to refuse.', 'basic-firewall' )
		);

		$this->row(
			__( 'Weight', 'basic-firewall' ),
			self::text( 'weight', (string) $rule['weight'], 'number', 'min="-1000" max="1000"' ),
			__( 'Lower runs first. Put cheap checks (address, path) ahead of expensive ones (Core Rule Set, IP reputation) so obvious traffic is dealt with before anything costly runs.', 'basic-firewall' )
		);

		if ( $type->supports_shared_status_code() ) {
			$this->row(
				__( 'Status code', 'basic-firewall' ),
				self::text( 'status_code', (string) $rule['status_code'], 'number', 'min="0" max="599"' ),
				__( '0 uses the site-wide code from the General screen.', 'basic-firewall' ),
				// A redirect carries its own status, and a mark never answers
				// the request at all, so neither has any use for this one.
				'response:!redirect|mark'
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

		$providers = array( '' => __( 'Use the site default', 'basic-firewall' ) );

		foreach ( Library_Map::CHALLENGE_PROVIDERS as $key => $label ) {
			$providers[ $key ] = $label;
		}

		$this->row(
			__( 'Challenge provider', 'basic-firewall' ),
			self::select( 'challenge_provider', $providers, (string) $rule['challenge_provider'] ),
			__( 'Overrides the provider chosen on the Challenge screen, for this rule only.', 'basic-firewall' ),
			'response:challenge'
		);

		$this->render_response_rows( $rule );

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

		// Offered only where the library keeps it; see has_rule_schedule().
		if ( ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_rule_schedule() ) {
			$this->render_schedule( (array) ( $rule['schedule'] ?? array() ) );
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
	 * Rows that belong to a redirect, a mark, or the record choice.
	 *
	 * Every row is rendered whatever the stored response, and the admin script
	 * shows the ones the selected response reads. These used to be rendered
	 * only for the response already saved, so choosing Redirect on a new rule
	 * offered nowhere to type the destination until after a first save -- and
	 * that first save stored a redirect rule naming nowhere. With JavaScript
	 * off every row stays visible, and the handler stores only the ones the
	 * chosen response reads.
	 *
	 * @param array<string, mixed> $rule The rule being edited.
	 */
	private function render_response_rows( array $rule ): void {
		if ( ! ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_record_control() ) {
			return;
		}

		$this->row(
			__( 'Send the visitor to', 'basic-firewall' ),
			self::text( 'redirect_to', (string) $rule['redirect_to'], 'text', 'placeholder="/why-was-i-redirected"' ),
			__( 'A path on this site such as <code>/too-many-requests</code>, or a full URL. <strong>Required</strong>: a redirect rule naming nowhere turns every request it matches into a firewall error. A redirect is the gentler answer when you are fairly sure but not certain — the visitor gets somewhere to read rather than a refusal with no explanation.', 'basic-firewall' ),
			'response:redirect'
		);

		$this->row(
			__( 'Redirect status', 'basic-firewall' ),
			self::select(
				'redirect_status',
				array(
					'302' => __( '302 — temporary (recommended)', 'basic-firewall' ),
					'307' => __( '307 — temporary, keeps the method', 'basic-firewall' ),
					'301' => __( '301 — permanent', 'basic-firewall' ),
					'308' => __( '308 — permanent, keeps the method', 'basic-firewall' ),
				),
				(string) $rule['redirect_status']
			),
			__( 'Keep this temporary unless you are certain. A rule\'s verdict changes with the next edit, and a <strong>301 is cached by browsers and intermediaries more or less forever</strong> — somebody caught by a rule you later tune would keep being sent to the notice page long after the rule stopped matching them.', 'basic-firewall' ),
			'response:redirect'
		);

		$this->row(
			__( 'Mark the request as', 'basic-firewall' ),
			self::text( 'mark_as', (string) $rule['mark_as'], 'text', 'placeholder="' . esc_attr( (string) $rule['id'] ) . '"' ),
			__( 'Left blank, the rule\'s own identifier is used. Letters, numbers, hyphens and underscores, because the name is what your code looks for. A marked request is <strong>allowed through</strong> and flagged, which is what a honeypot wants: you find out who tripped it without telling them they did.', 'basic-firewall' ),
			'response:mark'
		);

		$this->row(
			__( 'Also set this header', 'basic-firewall' ),
			self::text( 'mark_header', (string) $rule['mark_header'], 'text', 'placeholder="X-Firewall-Flagged"' ),
			__( 'Optional. Useful when something downstream — your application, a CDN, a log pipeline — is what acts on the mark.', 'basic-firewall' ),
			'response:mark'
		);

		printf(
			'<tr data-bfw-show-when="response:record"><th scope="row">%s</th><td><p class="description">%s</p></td></tr>',
			esc_html__( 'What this does', 'basic-firewall' ),
			wp_kses_post(
				__( 'The client is added to the block list and <strong>this request is still served</strong>. That is what a honeypot needs: a rule catching a scanner on a bait URL wants it blocked <em>next</em> time, not to refuse the fetch it is already answering — refusing tells the scanner exactly which URL is wired, which is the one thing a honeypot must not do.', 'basic-firewall' )
			)
		);

		/*
		 * Written out rather than through row(), because what "default" means
		 * depends on the response and the response can change without a
		 * reload. The option says both; the explanation beneath follows the
		 * select.
		 */
		printf(
			'<tr data-bfw-show-when="response:block|redirect|mark"><th scope="row">%s</th><td>%s<p class="description" data-bfw-show-when="response:block">%s</p><p class="description" data-bfw-show-when="response:redirect|mark">%s</p></td></tr>',
			esc_html__( 'Record the client', 'basic-firewall' ),
			wp_kses(
				self::select(
					'record',
					array(
						'default' => __( 'Default — a block records the client, a redirect or mark does not', 'basic-firewall' ),
						'yes'     => __( 'Yes — add the client to the block list', 'basic-firewall' ),
						'no'      => __( 'No — act on this request, and record nothing', 'basic-firewall' ),
					),
					(string) $rule['record']
				),
				self::allowed_control_html()
			),
			wp_kses_post( __( 'Recording adds the client to the durable block list, so later requests are refused without re-evaluating. <strong>Set this to No for a temporary lockdown</strong> — a rule that refuses everybody and records them leaves a block list full of customers once it is lifted, each on an escalating ban nobody asked for. Lockdown on the General screen is that, already built: everyone but an allowlist refused, nobody recorded.', 'basic-firewall' ) ),
			wp_kses_post( __( 'This response does not record by default, which is usually right — a honeypot that banned everyone who tripped it would stop being a honeypot. Set it to Yes if tripping this rule should also earn a block.', 'basic-firewall' ) )
		);
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

			/*
			 * A condition type's own settings beyond its conditions, where it
			 * describes them. Only the described ones: an undescribed nested
			 * map has no generic control, and a textarea of "Array" would be
			 * worse than nothing. A described one -- the geolocation reader --
			 * lists its fields, and each is rendered on its own.
			 *
			 * Without this the user agent rule's cache and bot-source settings
			 * were never on the page -- so every save through it posted neither,
			 * and turned the detection cache off.
			 */
			$extras = array_keys( array_diff_key( $type->settings_help(), array_flip( array( 'match_type', 'conditions', 'sources' ) ) ) );

			if ( array() !== $extras ) {
				$this->render_generic_settings( $type, $settings, $extras );
			}
		} else {
			$this->render_generic_settings( $type, $settings );
		}

		if ( $type->supports_sources() ) {
			$this->render_sources( $type, $settings );
		}
	}

	/**
	 * When the rule is awake.
	 *
	 * Needs library 2.27.0. Before it, "block this country outside business
	 * hours" and "turn this limit on for the campaign" were both answered the
	 * same way: comment the rule out, and remember to put it back.
	 *
	 * Folded away, because most rules are always on and a schedule that has to
	 * be dismissed on every edit is worse than one that has to be opened.
	 *
	 * @param array<string, mixed> $schedule The rule's stored schedule.
	 */
	private function render_schedule( array $schedule ): void {
		$set = array() !== Rule_Type_Base::schedule_declaration( $schedule );

		printf(
			'<details class="bfw-import"%s><summary>%s</summary>',
			$set ? ' open' : '',
			esc_html__( 'When this rule is awake', 'basic-firewall' )
		);

		printf(
			'<p>%s</p>',
			esc_html__( 'Leave this alone and the rule is always on, which is what nearly every rule wants. Fill any of it in and the rule is evaluated only inside the window — a sleeping rule is skipped before it costs a lookup, so a scheduled rate limit does not spend its budget while it is off.', 'basic-firewall' )
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Timezone', 'basic-firewall' ),
			self::select( 'schedule_timezone', $this->timezone_options(), (string) ( $schedule['timezone'] ?? '' ) ),
			esc_html__( 'Hours and dates below are read on this timezone\'s wall clock, so a window means what somebody standing there would say it means — across a daylight-saving change included.', 'basic-firewall' )
		);

		echo '<tr><th scope="row">' . esc_html__( 'Days', 'basic-firewall' ) . '</th><td><fieldset>';

		$chosen = array_map( 'strval', (array) ( $schedule['days'] ?? array() ) );

		foreach ( $this->day_options() as $day => $label ) {
			printf(
				'<label style="margin-right:1em"><input type="checkbox" name="schedule_days[]" value="%s"%s /> %s</label>',
				esc_attr( $day ),
				checked( in_array( $day, $chosen, true ), true, false ),
				esc_html( $label )
			);
		}

		echo '</fieldset><p class="description">' . esc_html__( 'None ticked means every day.', 'basic-firewall' ) . '</p></td></tr>';

		$this->row(
			__( 'Hours', 'basic-firewall' ),
			self::text( 'schedule_hours', (string) ( $schedule['hours'] ?? '' ), 'text', 'placeholder="18:00-06:00"' ),
			esc_html__( 'A range on the 24-hour clock, or several separated by commas, such as 09:00-12:00, 13:00-17:00. One that ends earlier than it starts runs overnight, so 18:00-06:00 is the evening through to the morning rather than an empty window.', 'basic-firewall' )
		);

		$this->row(
			__( 'Not before', 'basic-firewall' ),
			self::text( 'schedule_from', (string) ( $schedule['from'] ?? '' ), 'text', 'placeholder="2026-11-24"' )
			. ' ' . esc_html__( 'and not after', 'basic-firewall' ) . ' '
			. self::text( 'schedule_until', (string) ( $schedule['until'] ?? '' ), 'text', 'placeholder="2026-12-02"' ),
			esc_html__( 'Dates, for a rule that exists for one campaign or one maintenance window. Leave both blank for a rule with no end.', 'basic-firewall' )
		);

		echo '</tbody></table></details>';
	}

	/**
	 * Days, in the spelling the library reads.
	 *
	 * @return array<string, string>
	 */
	private function day_options(): array {
		return array(
			'mon' => __( 'Mon', 'basic-firewall' ),
			'tue' => __( 'Tue', 'basic-firewall' ),
			'wed' => __( 'Wed', 'basic-firewall' ),
			'thu' => __( 'Thu', 'basic-firewall' ),
			'fri' => __( 'Fri', 'basic-firewall' ),
			'sat' => __( 'Sat', 'basic-firewall' ),
			'sun' => __( 'Sun', 'basic-firewall' ),
		);
	}

	/**
	 * Timezones, with the site's own offered first.
	 *
	 * WordPress already knows which timezone this site thinks in, and a
	 * schedule written in a different one is almost always a mistake rather
	 * than a choice.
	 *
	 * @return array<string, string>
	 */
	private function timezone_options(): array {
		$site = wp_timezone_string();

		$options = array( '' => __( 'This site\'s timezone', 'basic-firewall' ) . ( '' !== $site ? ' — ' . $site : '' ) );

		foreach ( timezone_identifiers_list() as $zone ) {
			$options[ $zone ] = $zone;
		}

		return $options;
	}

	/**
	 * The referenced-list editor.
	 *
	 * Repeatable, with one blank row beyond what exists, and no JavaScript --
	 * the same arrangement the condition editor uses, for the same reason: a
	 * form that needs scripting to add a row is a form that cannot be used when
	 * the scripting fails.
	 *
	 * The fields are split into the ones nearly every list needs and an
	 * advanced block for the ones that are genuinely nested. A published list
	 * is rarely just a list: AWS publishes JSON that has to be filtered by
	 * service and projected down to one key, a CSV feed has a header row and a
	 * column, a private feed needs a bearer token. Offering only a URL would
	 * cover the easy half and quietly exclude the rest.
	 *
	 * @param Rule_Type            $type     The rule type.
	 * @param array<string, mixed> $settings Current settings.
	 */
	private function render_sources( Rule_Type $type, array $settings ): void {
		$sources = array_values(
			array_filter(
				(array) ( $settings['sources'] ?? array() ),
				static fn ( $source ): bool => is_array( $source ) && '' !== trim( (string) ( $source['url'] ?? '' ) )
			)
		);

		printf( '<h2>%s</h2>', esc_html__( 'Referenced lists', 'basic-firewall' ) );

		printf(
			'<p class="bfw-repeat-intro">%s</p>',
			wp_kses_post(
				__( 'Name a published list by URL instead of pasting its contents here. The list is fetched on a schedule and never while a visitor waits — the request path reads a cached copy and nothing else, so an outage at the provider cannot become latency on this site. Use it for anything somebody else maintains and changes without telling you: a monitoring provider\'s probe addresses, a CDN\'s egress ranges, a threat feed.', 'basic-firewall' )
			)
		);

		echo '<div data-bfw-repeatable="sources">';

		foreach ( $sources as $index => $source ) {
			$this->render_source( $type, $index, array_merge( Ip_Address::source_defaults(), (array) $source ), false );
		}

		/*
		 * One blank card, always present and always last.
		 *
		 * It is what makes "Add list" work with JavaScript off: the button
		 * below clones this card and renumbers it, and where it cannot, the
		 * blank one is still a usable form that adds a list per save. The
		 * alternative -- three spare cards rendered open -- was what this
		 * replaced, and a screen that shows four empty copies of an
		 * eleven-field form does not read as "add one if you want one".
		 */
		$this->render_source( $type, count( $sources ), Ip_Address::source_defaults(), true );

		echo '</div>';

		printf(
			'<p><button type="button" class="button" data-bfw-add="sources">%s</button></p>',
			esc_html__( '+ Add list', 'basic-firewall' )
		);
	}

	/**
	 * One referenced list, as a card.
	 *
	 * Grouped rather than run together, because eleven fields in one flat table
	 * gives no clue which belong to which list, and most of them are wanted by
	 * almost nobody. What a plain text list needs is the URL; everything about
	 * interpreting a structured document is folded away behind a summary until
	 * somebody has a structured document to interpret.
	 *
	 * @param Rule_Type            $type   The rule type.
	 * @param int                  $index  Position in the list.
	 * @param array<string, mixed> $source Its settings.
	 * @param bool                 $blank  Whether this is the empty "new" card.
	 */
	private function render_source( Rule_Type $type, int $index, array $source, bool $blank ): void {
		$name  = static fn ( string $key ): string => sprintf( 'settings[sources][%d][%s]', $index, $key );
		$title = trim( (string) $source['name'] );

		if ( '' === $title ) {
			$title = trim( (string) $source['url'] );
		}

		printf(
			'<div class="bfw-repeat__item%s" data-bfw-item>',
			$blank ? ' bfw-repeat__item--new' : ''
		);

		printf(
			'<div class="bfw-repeat__head"><strong>%s</strong>%s</div>',
			esc_html( '' !== $title ? $title : __( 'New list', 'basic-firewall' ) ),
			$blank
				? ''
				: sprintf(
					'<button type="button" class="button-link bfw-repeat__remove" data-bfw-remove>%s</button>',
					esc_html__( 'Remove', 'basic-firewall' )
				)
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'List URL', 'basic-firewall' ),
			self::text( $name( 'url' ), (string) $source['url'], 'text', 'class="large-text" placeholder="https://example.com/ips.txt"' ),
			esc_html__( 'An http(s) URL, or a filename inside the firewall\'s private directory. Clearing this removes the list.', 'basic-firewall' )
		);

		$this->row(
			__( 'Name', 'basic-firewall' ),
			self::text( $name( 'name' ), (string) $source['name'], 'text', 'placeholder="' . esc_attr__( 'the rule identifier', 'basic-firewall' ) . '"' ),
			esc_html__( 'Optional. Used in log lines and refresh failures.', 'basic-firewall' )
		);

		$this->row(
			__( 'Refresh', 'basic-firewall' ),
			self::text( $name( 'ttl' ), (string) $source['ttl'], 'number' )
			. ' ' . esc_html__( 'seconds, and if it cannot be fetched:', 'basic-firewall' )
			. ' ' . self::select( $name( 'on_error' ), Ip_Address::error_policies(), (string) $source['on_error'] ),
			wp_kses_post(
				__( 'The default error policy is almost always right. <strong>Drop the list</strong> turns a provider outage into this rule matching fewer addresses, which on an allow rule means blocking the very thing it exists to permit.', 'basic-firewall' )
			)
		);

		echo '</tbody></table>';

		/*
		 * Everything below is about reading a document that is not already a
		 * list of addresses. Closed by default, and closed is the right default:
		 * a .txt of addresses -- which is what most published lists are -- needs
		 * none of it.
		 */
		printf( '<details class="bfw-repeat__more"><summary>%s</summary>', esc_html__( 'Shaping and safeguards', 'basic-firewall' ) );

		printf(
			'<p class="description">%s</p>',
			esc_html__( 'Only needed when the list is not already one address per line — a JSON document that has to be picked apart, a CSV column, a feed that needs filtering.', 'basic-firewall' )
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Format', 'basic-firewall' ),
			self::select( $name( 'format' ), Ip_Address::formats(), (string) $source['format'] )
			. ' ' . self::select( $name( 'compression' ), Ip_Address::compressions(), (string) $source['compression'] ),
			esc_html__( 'Both are worked out from the URL when left to detect, which is right for a .txt or a .json.gz and wrong for a URL that ends in neither.', 'basic-firewall' )
		);

		$this->row(
			__( 'Select', 'basic-firewall' ),
			self::text( $name( 'select' ), (string) $source['select'], 'text', 'placeholder="prefixes.*"' ),
			wp_kses_post(
				__( 'A dot-path to the records, ending in <code>.*</code> to iterate them. AWS publishes its ranges under <code>prefixes.*</code>, GitHub under <code>actions.*</code>. Without the <code>.*</code> the whole array is taken as a single record and the list contributes one unusable entry.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Template', 'basic-firewall' ),
			self::text( $name( 'template' ), (string) $source['template'], 'text', 'placeholder="{value[ip_prefix]}"' ),
			wp_kses_post(
				__( 'What to make of each record. <code>{value}</code> is the record itself; index into it when it is structured, so AWS\'s objects become addresses with <code>{value[ip_prefix]}</code> and a CSV column is <code>{value[cidr]}</code>. Use <code>{value[ip_prefix|ipv6_prefix]}</code> to take whichever key exists.', 'basic-firewall' )
			)
		);

		/*
		 * The one field that differs by family, and the reason lists work on
		 * both. An address rule takes each entry as it stands; a condition rule
		 * has to be told what to compare it against, and answering that here
		 * means the administrator never has to write a template by hand.
		 */
		if ( $type instanceof Condition_Rule_Type_Base ) {
			$reflector = new \ReflectionMethod( $type, 'variable_options' );
			$reflector->setAccessible( true );

			/**
			 * The variables this rule type can read.
			 *
			 * @var array<string, string> $variables
			 */
			$variables = $reflector->invoke( $type );

			$options = array( '' => __( '— choose —', 'basic-firewall' ) );

			foreach ( array_keys( $variables ) as $variable ) {
				$options[ (string) $variable ] = (string) $variable;
			}

			$current = (string) $source['variable'];

			/*
			 * A prefixed variable is not in the options list and is perfectly
			 * readable -- the list names the families, and `header.user-agent`
			 * is a member of one. Without this it rendered as nothing selected
			 * and was lost on the next save, which is the condition editor's
			 * problem solved the same way a few hundred lines below.
			 */
			if ( '' !== $current && ! isset( $options[ $current ] ) ) {
				$options[ $current ] = $current;
			}

			$this->row(
				__( 'Match each entry against', 'basic-firewall' ),
				self::select( $name( 'variable' ), $options, $current )
				. ' ' . self::select( $name( 'operator' ), Condition_Rule_Type_Base::OPERATORS, (string) $source['operator'] )
				. ' ' . self::checkbox( $name( 'negate' ), ! empty( $source['negate'] ), __( 'Invert', 'basic-firewall' ) ),
				wp_kses_post(
					__( 'Each line of the list becomes one condition. A list of crawler names matched with <strong>user agent header</strong> and <strong>contains</strong> is the usual arrangement — and the reason a list is worth referencing at all, since the names change weekly and the rule does not.', 'basic-firewall' )
				)
			);
		}

		$this->row(
			__( 'Check each entry is', 'basic-firewall' ),
			self::select( $name( 'validate' ), Ip_Address::validators(), (string) $source['validate'] ),
			esc_html__( 'Asserted per entry at refresh, so a feed that starts emitting hostnames is rejected outright rather than contributing entries that silently match nothing.', 'basic-firewall' )
		);

		$this->row(
			__( 'Reject a change larger than', 'basic-firewall' ),
			self::text( $name( 'max_delta' ), (string) $source['max_delta'], 'text', 'placeholder="0.5"' ),
			esc_html__( 'A fraction, so 0.5 refuses a refresh that moves the entry count by more than half. This is the guard against a provider serving a truncated or empty file: without it, an allow list that briefly returns nothing silently stops allowing. Blank for no limit.', 'basic-firewall' )
		);

		$this->row(
			__( 'Verify the bytes', 'basic-firewall' ),
			self::select( $name( 'checksum' ), Ip_Address::checksums(), (string) $source['checksum'] ),
			wp_kses_post(
				__( 'Checks the list against a sidecar published beside it — <code>&lt;url&gt;.sha256</code>. HTTPS proves you reached the right host; it says nothing about a repository that was compromised, a CDN object that was replaced, or a publisher who pushed the wrong file.<br><br>A sidecar on the same host raises the bar without clearing it: anyone who can replace the list can replace the sidecar. For a pinned key that does close it, write <code>signature:</code> in the advanced block below.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Refuse anything larger than', 'basic-firewall' ),
			self::text( $name( 'max_size' ), (string) $source['max_size'], 'text', 'placeholder="32M"' ),
			wp_kses_post(
				__( 'Blank uses the firewall\'s own 32 MiB. Applied <strong>after decompression</strong>, which is the case that matters: a 100 KB gzip of ordinary repetitive list data decodes to tens of megabytes, and a <code>.gz</code> URL turns compression on without anybody choosing it. An oversized list is refused rather than truncated — half a block list is a list whose meaning nobody knows, and it looks exactly like a list that is simply shorter this week.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Required', 'basic-firewall' ),
			self::checkbox( $name( 'required' ), ! empty( $source['required'] ), __( 'A failure to load this list stops the firewall starting', 'basic-firewall' ) ),
			esc_html__( 'Overrides the error policy above. Only correct where the list is a compliance boundary and running without it is worse than not running.', 'basic-firewall' )
		);

		$advanced = $source['advanced'];

		$this->row(
			__( 'Advanced', 'basic-firewall' ),
			self::textarea(
				$name( 'advanced' ),
				is_array( $advanced ) && array() !== $advanced ? Yaml::dump( $advanced, 6, 2 ) : ( is_string( $advanced ) ? $advanced : '' ),
				5,
				true
			),
			wp_kses_post(
				/* translators: the %env()% below is a literal token the firewall reads, not a placeholder. */
				__( 'YAML for everything the fields above do not cover, merged into this list\'s definition.<br><br><code>where:</code> filters the records, using the same condition syntax the rest of the firewall uses, against the record\'s own keys — <code>- service@equals:CLOUDFRONT</code> reduces AWS\'s 10,000 prefixes to CloudFront\'s. Every rule must pass, so the list narrows as you add them.<br><br>Also here: a nested <code>template:</code> map, <code>header_row</code>, <code>delimiter</code> and <code>comment</code> for CSV, and <code>upstream:</code> for a credential, extra headers, a method or a body. A credential belongs in a <code>%env()%</code> token rather than typed literally — exports strip <code>upstream.auth</code> and say they did.', 'basic-firewall' )
			)
		);

		echo '</tbody></table></details></div>';
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
			__( 'Name', 'basic-firewall' ),
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

			$stored = (string) ( $condition['variable'] ?? '' );

			/*
			 * Split into what to look at and which one, the way the Drupal
			 * module does it.
			 *
			 * The families are the reason. A condition can read `query.test`,
			 * `header.x-api-key` or any cookie by name, and all of it was
			 * unreachable here: the select listed the ten named variables, so
			 * the only routes to a named one were WP-CLI, an imported document
			 * or the advanced YAML. A second column keeps the first one closed
			 * -- no typing `quest` for `query` -- and asks for the name only
			 * when the choice actually takes one.
			 */
			list( $current, $member ) = $this->split_variable( $type, $stored );

			$options = array( '' => __( '— choose —', 'basic-firewall' ) );

			foreach ( $variables as $variable => $label ) {
				$options[ (string) $variable ] = (string) $variable;
			}

			foreach ( $this->variable_families( $type ) as $family => $label ) {
				$options[ $family ] = $family;
			}

			// Anything stored that this type no longer offers still has to
			// render, or editing an unrelated field would silently drop it.
			if ( '' !== $current && ! isset( $options[ $current ] ) ) {
				$options[ $current ] = $current;
			}

			echo wp_kses( self::select( $name . '[variable]', $options, $current ), self::allowed_control_html() );

			$families = $this->variable_families( $type );

			if ( isset( $variables[ $current ] ) ) {
				printf( '<p class="description">%s</p>', esc_html( $variables[ $current ] ) );
			} elseif ( isset( $families[ $current ] ) ) {
				printf( '<p class="description">%s</p>', esc_html( $families[ $current ] ) );
			}

			echo '</td><td>';

			printf(
				'<span data-bfw-show-when="%s">%s</span>',
				esc_attr( $name . '[variable]:' . implode( '|', array_keys( $families ) ) ),
				wp_kses(
					self::text( $name . '[variable_name]', $member, 'text', 'placeholder="' . esc_attr__( 'test', 'basic-firewall' ) . '"' ),
					self::allowed_control_html()
				)
			);

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

			printf(
				'<p class="description" data-bfw-show-when="%s">%s</p>',
				esc_attr( $name . '[operator]:regex' ),
				esc_html__( 'The pattern only — no delimiters. Those and the case flag are added for you, so ^/wp-admin is written exactly like that.', 'basic-firewall' )
			);

			echo '</td><td>';

			echo wp_kses( self::checkbox( $name . '[negate]', ! empty( $condition['negate'] ), __( 'Negate', 'basic-firewall' ) ), self::allowed_control_html() );

			echo '<br>';

			/*
			 * Offered on every operator, regular expressions included. The
			 * pattern is stored as its body and the delimiters and `i` flag are
			 * added at compile time, so this box means the same thing here as
			 * it does anywhere else -- which is the point of storing it that
			 * way.
			 */
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
	 * @param list<string>|null    $only     Render only these keys, or all when null.
	 */
	private function render_generic_settings( Rule_Type $type, array $settings, ?array $only = null ): void {
		$help = $type->settings_help();

		echo '<table class="form-table" role="presentation"><tbody>';

		foreach ( $type->default_settings() as $key => $default ) {
			// Rendered by its own editor below, not as a textarea of nothing.
			if ( 'sources' === $key && $type->supports_sources() ) {
				continue;
			}

			if ( null !== $only && ! in_array( (string) $key, $only, true ) ) {
				continue;
			}

			$field = (array) ( $help[ $key ] ?? array() );
			$value = $settings[ $key ] ?? $default;

			/*
			 * A nested map the type has described field by field -- the
			 * geolocation reader, whose source, database path and CDN live
			 * under one key. Each described field is its own row, named
			 * `settings[reader][source]`, so it posts back into the same shape
			 * it was read from.
			 *
			 * Before this the reader was never on the page, so a save through
			 * this screen posted none of it: the type's validator saw an empty
			 * reader, and a rule reading from a database was refused for having
			 * no path, or one reading from the CDN was quietly put back on a
			 * database it did not have.
			 */
			if ( is_array( $default ) && is_array( $field['fields'] ?? null ) ) {
				$value = is_array( $value ) ? $value : array();

				foreach ( (array) $field['fields'] as $child => $child_field ) {
					if ( ! array_key_exists( $child, $default ) ) {
						continue;
					}

					$this->render_setting_row(
						$type,
						sprintf( 'settings[%s][%s]', $key, $child ),
						$key . '.' . $child,
						$default[ $child ],
						$value[ $child ] ?? $default[ $child ],
						(array) $child_field
					);
				}

				continue;
			}

			$this->render_setting_row( $type, sprintf( 'settings[%s]', $key ), (string) $key, $default, $value, $field );
		}

		echo '</tbody></table>';
	}

	/**
	 * One settings row, with a control chosen from the default value.
	 *
	 * @param Rule_Type            $type    The rule type.
	 * @param string               $name    The control's name attribute.
	 * @param string               $path    The setting's dotted path, as secret_settings() names it.
	 * @param mixed                $initial The default value, which decides the control.
	 * @param mixed                $value   The current value.
	 * @param array<string, mixed> $field   The type's description of the setting.
	 */
	private function render_setting_row( Rule_Type $type, string $name, string $path, $initial, $value, array $field ): void {
		$secret = in_array( $path, $type->secret_settings(), true );
		$label  = (string) ( $field['label'] ?? $this->humanize( (string) substr( (string) strrchr( '.' . $path, '.' ), 1 ) ) );

		// Shown only while another control holds a value, as `field:value`.
		$show_when = (string) ( $field['show_when'] ?? '' );

		if ( is_bool( $initial ) ) {
			$this->row(
				$label,
				self::checkbox( $name, (bool) $value, (string) ( $field['checkbox'] ?? __( 'Enabled', 'basic-firewall' ) ) ),
				wp_kses_post( (string) ( $field['description'] ?? '' ) ),
				$show_when
			);

			return;
		}

		if ( ! empty( $field['secret'] ) ) {
			$this->render_secret_row( $name, $label, $value, $field, $show_when );

			return;
		}

		if ( is_array( $initial ) ) {
			$lines = array();

			/*
			 * A map is written a pair to a line, as `key: value`, which is the
			 * shape its validator reads back -- the reader's header mapping is
			 * one. Imploding the values alone would drop the keys and post back
			 * something the validator refuses.
			 *
			 * A type that stores its lines as something richer -- the rate
			 * limit keeps each limit as a map -- says how to write them back,
			 * so the textarea holds what its validator reads rather than
			 * "Array".
			 */
			if ( isset( $field['lines'] ) && is_callable( $field['lines'] ) ) {
				$text = (string) call_user_func( $field['lines'], $value );
			} else {
				foreach ( is_array( $value ) ? $value : array( $value ) as $item_key => $item ) {
					$lines[] = is_string( $item_key ) ? $item_key . ': ' . (string) $item : (string) $item;
				}

				$text = implode( "\n", $lines );
			}

			$this->row(
				$label,
				self::textarea( $name, $text ),
				wp_kses_post( (string) ( $field['description'] ?? __( 'One per line.', 'basic-firewall' ) ) ),
				$show_when
			);

			return;
		}

		// A fixed set of answers is a select, not a text field somebody has
		// to guess the spelling of.
		if ( is_array( $field['choices'] ?? null ) && array() !== $field['choices'] ) {
			$this->row(
				$label,
				self::select( $name, $field['choices'], (string) $value ),
				wp_kses_post( (string) ( $field['description'] ?? '' ) ),
				$show_when
			);

			return;
		}

		$description = wp_kses_post( (string) ( $field['description'] ?? '' ) );

		if ( $secret ) {
			/*
			 * Warned at the point the key is typed, not in a readme. A literal
			 * key here is stored in the options table and travels in a database
			 * export; a token names a variable instead.
			 */
			/* translators: %s: the value described in the sentence. */
			$description = trim( $description . ' ' . __( 'This is a credential. Prefer a token — <code>%env(MY_VARIABLE)%</code> — over the value itself: a token is exported and backed up safely, and a rotated value is picked up without a rebuild. Exports strip a literal value and say so.', 'basic-firewall' ) );
		}

		$this->row(
			$label,
			self::text( $name, (string) $value, is_int( $initial ) ? 'number' : 'text' ),
			$description,
			$show_when
		);
	}

	/**
	 * A credential row: typed, never shown.
	 *
	 * The stored value is not put back into the page, where it would sit in
	 * the page source, the browser's form cache and every screenshot of the
	 * screen. Blank keeps it; the box removes it. See with_secret_fields().
	 *
	 * @param string               $name      The control's name attribute.
	 * @param string               $label     The row label.
	 * @param mixed                $value     The stored value.
	 * @param array<string, mixed> $field     The type's description of the setting.
	 * @param string               $show_when When the row is shown.
	 */
	private function render_secret_row( string $name, string $label, $value, array $field, string $show_when ): void {
		$stored = is_string( $value ) && '' !== $value;
		$clear  = 'clear_secret' . substr( $name, strlen( 'settings' ) );

		$control = self::text( $name, '', 'password', 'autocomplete="new-password"' )
			. ( $stored ? '<br>' . self::checkbox( $clear, false, __( 'Remove the stored value', 'basic-firewall' ) ) : '' );

		$this->row(
			$label,
			$control,
			wp_kses_post(
				trim(
					( $stored ? __( 'A value is stored. Leave blank to keep it.', 'basic-firewall' ) . ' ' : '' )
					. (string) ( $field['description'] ?? '' ) . ' '
					/* translators: the %env()% below is a literal token the firewall reads, not a placeholder. */
					. __( 'This is a credential. Prefer a token — <code>%env(MY_VARIABLE)%</code> — over the value itself: a token is exported and backed up safely, and a rotated value is picked up without a rebuild. Exports strip a literal value and say so.', 'basic-firewall' )
				)
			),
			$show_when
		);
	}

	/**
	 * Name a failing field in terms of what is on the screen.
	 *
	 * A validator reports where it found the problem, which for a repeatable
	 * block is `sources.1.url`. Printed as-is that is accurate and no help:
	 * there is nothing on the page called `sources.1.url`, and the reader has
	 * to work out that lists are zero-indexed before they know which card to
	 * look at.
	 *
	 * @param string $field Dotted field path from the validator.
	 */
	private function field_label( string $field ): string {
		if ( 1 === preg_match( '/^sources\.(\d+)\.(.+)$/', $field, $matches ) ) {
			return sprintf(
				/* translators: 1: position of the list on screen, 2: the field within it. */
				__( 'Referenced list %1$d — %2$s', 'basic-firewall' ),
				(int) $matches[1] + 1,
				$this->humanize( str_replace( '.', ' ', $matches[2] ) )
			);
		}

		return $this->humanize( $field );
	}

	/**
	 * The prefixed families this type can read, described.
	 *
	 * A family is not a variable: `query` reads nothing, `query.test` reads a
	 * parameter. The select offers the family and the Name column supplies the
	 * rest, which is why these are kept apart from `variable_options()`.
	 *
	 * @param Rule_Type $type The rule type.
	 *
	 * @return array<string, string>
	 */
	private function variable_families( Rule_Type $type ): array {
		$reflector = new \ReflectionMethod( $type, 'variable_prefixes' );
		$reflector->setAccessible( true );

		$described = array(
			'query'  => __( 'A query parameter — name it alongside', 'basic-firewall' ),
			'header' => __( 'A request header — name it alongside', 'basic-firewall' ),
			'cookie' => __( 'A cookie — name it alongside', 'basic-firewall' ),
			'post'   => __( 'A posted field — name it alongside', 'basic-firewall' ),
		);

		$families = array();

		foreach ( (array) $reflector->invoke( $type ) as $prefix ) {
			$prefix = (string) $prefix;

			$families[ $prefix ] = $described[ $prefix ] ?? sprintf(
				/* translators: %s: the family name, such as query or header. */
				__( 'A %s value — name it alongside', 'basic-firewall' ),
				$prefix
			);
		}

		return $families;
	}

	/**
	 * Split a stored variable into its family and its name.
	 *
	 * `query.test` is two fields on screen and one string in storage, because
	 * one string is what the library reads and what every export, import and
	 * CLI command already carries. Splitting for display rather than storing
	 * two keys keeps that untouched.
	 *
	 * Only the first dot separates: a header is `header.x-forwarded-for` and a
	 * cookie can be named almost anything.
	 *
	 * @param Rule_Type $type   The rule type.
	 * @param string    $stored The stored variable.
	 *
	 * @return array{0: string, 1: string} The family or variable, and the name.
	 */
	private function split_variable( Rule_Type $type, string $stored ): array {
		$position = strpos( $stored, '.' );

		if ( false === $position ) {
			return array( $stored, '' );
		}

		$family = substr( $stored, 0, $position );

		if ( ! isset( $this->variable_families( $type )[ $family ] ) ) {
			// A dotted name that is not a family -- `client.name` on the user
			// agent type -- is a whole variable and must not be taken apart.
			return array( $stored, '' );
		}

		return array( $family, substr( $stored, $position + 1 ) );
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
