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
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
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

		$settings = $type->validate_settings( $this->posted_array( 'settings' ), $errors );

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
		 * Validated by the library rather than here.
		 *
		 * `Schedule::fromMetadata()` is what will read this at runtime, and it
		 * throws with a message naming what it did not understand -- a timezone
		 * that is not a zone, an hours range that is not a range. Re-deriving
		 * those rules in this plugin would be two implementations that agree
		 * until they do not, and the one that matters is the library's.
		 */
		$declaration = Rule_Type_Base::schedule_declaration( $schedule );

		if ( array() !== $declaration ) {
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

		$rule = array(
			'id'                 => $id,
			'type'               => $type->id(),
			'label'              => $this->posted( 'label' ),
			'enabled'            => '' !== $this->posted( 'enabled' ),
			'response'           => $response,
			'weight'             => (int) $this->posted( 'weight', '0' ),
			'status_code'        => (int) $this->posted( 'status_code', '0' ),
			'challenge_provider' => $this->posted( 'challenge_provider' ),
			'record'             => $this->posted( 'record', 'default' ),
			'schedule'           => $schedule,
			'redirect_to'        => $this->posted( 'redirect_to' ),
			'redirect_status'    => (int) $this->posted( 'redirect_status', '302' ),
			'mark_as'            => $this->posted( 'mark_as' ),
			'mark_header'        => $this->posted( 'mark_header' ),
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
				'redirect'  => __( 'Redirect — send the visitor somewhere else', 'basic-firewall' ),
				'mark'      => __( 'Mark — let the request through, but flag it', 'basic-firewall' ),
				'record'    => __( 'Record — let the request through, and block them next time', 'basic-firewall' ),
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

		$this->render_schedule( (array) ( $rule['schedule'] ?? array() ) );

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
	 * @param array<string, mixed> $rule The rule being edited.
	 */
	private function render_response_rows( array $rule ): void {
		$response = (string) $rule['response'];

		if ( ! ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_record_control() ) {
			return;
		}

		if ( 'redirect' === $response ) {
			$this->row(
				__( 'Send the visitor to', 'basic-firewall' ),
				self::text( 'redirect_to', (string) $rule['redirect_to'], 'text', 'placeholder="/why-was-i-redirected"' ),
				__( 'A path on this site, or a full URL. A redirect is the gentler answer when you are fairly sure but not certain — the visitor gets somewhere to read rather than a refusal with no explanation.', 'basic-firewall' )
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
				__( 'Keep this temporary unless you are certain. A rule\'s verdict changes with the next edit, and a <strong>301 is cached by browsers and intermediaries more or less forever</strong> — somebody caught by a rule you later tune would keep being sent to the notice page long after the rule stopped matching them.', 'basic-firewall' )
			);
		}

		if ( 'mark' === $response ) {
			$this->row(
				__( 'Mark the request as', 'basic-firewall' ),
				self::text( 'mark_as', (string) $rule['mark_as'], 'text', 'placeholder="' . esc_attr( (string) $rule['id'] ) . '"' ),
				__( 'Left blank, the rule\'s own identifier is used. A marked request is <strong>allowed through</strong> and flagged, which is what a honeypot wants: you find out who tripped it without telling them they did.', 'basic-firewall' )
			);

			$this->row(
				__( 'Also set this header', 'basic-firewall' ),
				self::text( 'mark_header', (string) $rule['mark_header'], 'text', 'placeholder="X-Firewall-Flagged"' ),
				__( 'Optional. Useful when something downstream — your application, a CDN, a log pipeline — is what acts on the mark.', 'basic-firewall' )
			);
		}

		if ( 'record' === $response ) {
			printf(
				'<tr><th scope="row">%s</th><td><p class="description">%s</p></td></tr>',
				esc_html__( 'What this does', 'basic-firewall' ),
				wp_kses_post(
					__( 'The client is added to the block list and <strong>this request is still served</strong>. That is what a honeypot needs: a rule catching a scanner on a bait URL wants it blocked <em>next</em> time, not to refuse the fetch it is already answering — refusing tells the scanner exactly which URL is wired, which is the one thing a honeypot must not do.', 'basic-firewall' )
				)
			);
		}

		if ( in_array( $response, array( 'block', 'redirect', 'mark' ), true ) ) {
			$this->row(
				__( 'Record the client', 'basic-firewall' ),
				self::select(
					'record',
					array(
						'default' => 'block' === $response
							? __( 'Default — record the client, as a block normally does', 'basic-firewall' )
							: __( 'Default — do not record the client', 'basic-firewall' ),
						'yes'     => __( 'Yes — add the client to the block list', 'basic-firewall' ),
						'no'      => __( 'No — act on this request, and record nothing', 'basic-firewall' ),
					),
					(string) $rule['record']
				),
				'block' === $response
					? __( 'Recording adds the client to the durable block list, so later requests are refused without re-evaluating. <strong>Set this to No for a temporary lockdown</strong> — a rule that refuses everybody and records them leaves a block list full of customers once it is lifted, each on an escalating ban nobody asked for.', 'basic-firewall' )
					: __( 'This response does not record by default, which is usually right — a honeypot that banned everyone who tripped it would stop being a honeypot. Set it to Yes if tripping this rule should also earn a block.', 'basic-firewall' )
			);
		}
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
			esc_html__( 'A range on the 24-hour clock. One that ends earlier than it starts runs overnight, so 18:00-06:00 is the evening through to the morning rather than an empty window.', 'basic-firewall' )
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
	 */
	private function render_generic_settings( Rule_Type $type, array $settings ): void {
		$help = $type->settings_help();

		echo '<table class="form-table" role="presentation"><tbody>';

		foreach ( $type->default_settings() as $key => $default ) {
			// Rendered by its own editor below, not as a textarea of nothing.
			if ( 'sources' === $key && $type->supports_sources() ) {
				continue;
			}

			$value  = $settings[ $key ] ?? $default;
			$name   = sprintf( 'settings[%s]', $key );
			$secret = in_array( (string) $key, $type->secret_settings(), true );
			$field  = (array) ( $help[ $key ] ?? array() );
			$label  = (string) ( $field['label'] ?? $this->humanize( (string) $key ) );

			if ( is_bool( $default ) ) {
				$this->row(
					$label,
					self::checkbox( $name, (bool) $value, __( 'Enabled', 'basic-firewall' ) ),
					wp_kses_post( (string) ( $field['description'] ?? '' ) )
				);

				continue;
			}

			if ( is_array( $default ) ) {
				$this->row(
					$label,
					self::textarea( $name, is_array( $value ) ? implode( "\n", array_map( 'strval', $value ) ) : (string) $value ),
					wp_kses_post( (string) ( $field['description'] ?? __( 'One per line.', 'basic-firewall' ) ) )
				);

				continue;
			}

			// A fixed set of answers is a select, not a text field somebody has
			// to guess the spelling of.
			if ( is_array( $field['choices'] ?? null ) && array() !== $field['choices'] ) {
				$this->row(
					$label,
					self::select( $name, $field['choices'], (string) $value ),
					wp_kses_post( (string) ( $field['description'] ?? '' ) )
				);

				continue;
			}

			$description = wp_kses_post( (string) ( $field['description'] ?? '' ) );

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
				$label,
				self::text( $name, (string) $value, is_int( $default ) ? 'number' : 'text' ),
				$description
			);
		}

		echo '</tbody></table>';
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
			'server' => __( 'A server variable — name it alongside', 'basic-firewall' ),
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
