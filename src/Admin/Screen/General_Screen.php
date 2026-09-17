<?php
/**
 * Global firewall settings.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Health\Site_Health;
use Kanopi\BasicFirewall\Runtime\Trusted_Proxies;
use Kanopi\BasicFirewall\Sources\Refresher;

/**
 * Mode, responses, the proxy question, and escalation.
 */
final class General_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-general';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'General settings', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function menu_title(): string {
		return __( 'General', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function handle(): void {
		if ( ! $this->verify() ) {
			return;
		}

		$settings = $this->plugin()->settings();
		$all      = $settings->all();

		$all['enabled'] = '' !== $this->posted( 'enabled' );

		$all['global']['mode']                    = $this->posted( 'mode', 'log' );
		$all['global']['banning_status_code']     = $this->posted( 'banning_status_code', '403' );
		$all['global']['banning_message']         = $this->posted( 'banning_message' );
		$all['global']['repeat_offender_status']  = $this->posted( 'repeat_offender_status', '403' );
		$all['global']['add_to_expire']           = $this->posted( 'add_to_expire', '3600' );
		$all['global']['behind_proxy']            = $this->posted( 'behind_proxy', 'unknown' );
		$all['global']['require_trusted_proxies'] = '' !== $this->posted( 'require_trusted_proxies' );
		$all['global']['require_config']          = '' !== $this->posted( 'require_config' );

		$all['sources']['cron_interval'] = (int) $this->posted( 'sources_cron_interval', (string) DAY_IN_SECONDS );

		$roles = $this->posted_array( 'bypass_roles' );

		/*
		 * The anonymous equivalent is stripped rather than offered and ignored.
		 * Exempting every logged-out visitor would switch the firewall off for
		 * almost all traffic while the interface went on reporting "Blocking".
		 */
		$all['global']['bypass_roles'] = array_values(
			array_filter(
				array_map( 'strval', $roles ),
				static fn ( string $role ): bool => '' !== $role
			)
		);

		$problems = $settings->replace( $all );

		if ( array() !== $problems ) {
			foreach ( $problems as $problem ) {
				Notices::add(
					sprintf( '<strong>%s</strong>: %s', esc_html( $problem['path'] ), esc_html( $problem['message'] ) ),
					'error'
				);
			}
		} else {
			Notices::add( __( 'General settings saved, and the firewall recompiled.', 'basic-firewall' ) );
		}

		if ( 'block' === $all['global']['mode'] && array() !== $all['global']['bypass_roles'] ) {
			Notices::add(
				__( 'One or more roles are exempt from the firewall. Anyone who can grant such a role can exempt themselves, and an account takeover is unfiltered from that point on. An allow rule scoped to an address range leaves the rest of the firewall at full strength.', 'basic-firewall' ),
				'warning'
			);
		}

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$settings = $this->plugin()->settings();

		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Enable the firewall', 'basic-firewall' ),
			self::checkbox( 'enabled', (bool) $settings->get( 'enabled', true ), __( 'Evaluate incoming requests', 'basic-firewall' ) ),
			__( 'Unticking this stops all evaluation. <code>define( \'BASIC_FIREWALL_ENABLED\', false )</code> in wp-config.php does the same thing, needs no database access, and is the way out if a rule ever locks you out of your own site.', 'basic-firewall' )
		);

		$this->row(
			__( 'Operating mode', 'basic-firewall' ),
			self::select(
				'mode',
				array(
					'log'       => __( 'Log only — evaluate and record, block nothing', 'basic-firewall' ),
					'block'     => __( 'Block — reject matching requests', 'basic-firewall' ),
					'exception' => __( 'Exception — throw instead of responding (testing)', 'basic-firewall' ),
					'disabled'  => __( 'Disabled — evaluate nothing', 'basic-firewall' ),
				),
				(string) $settings->get( 'global.mode', 'log' )
			),
			__( 'The plugin installs in <strong>Log only</strong> on purpose. Add your rules, leave this alone for a few days, read the log for anything legitimate, and switch to Block once it is clean.', 'basic-firewall' )
		);

		$this->row(
			__( 'Status code for blocked clients', 'basic-firewall' ),
			self::text( 'banning_status_code', (string) $settings->get( 'global.banning_status_code', 403 ), 'number', 'min="100" max="599"' ),
			__( 'Used when the matching rule does not specify its own.', 'basic-firewall' )
		);

		$this->row(
			__( 'Message shown to blocked clients', 'basic-firewall' ),
			self::text( 'banning_message', (string) $settings->get( 'global.banning_message', '' ) ),
			__( 'Available variables: <code>{{request.id}}</code> for the reference, which is what <code>wp basic-firewall find-reference</code> looks up. Keep it short and free of detail about why — a rejected client does not need to know which rule caught them.', 'basic-firewall' )
		);

		$this->row(
			__( 'Status code for already-blocked clients', 'basic-firewall' ),
			self::text( 'repeat_offender_status', (string) $settings->get( 'global.repeat_offender_status', 403 ), 'number', 'min="100" max="599"' )
		);

		$this->row(
			__( 'Seconds added when a blocked client returns', 'basic-firewall' ),
			self::text( 'add_to_expire', (string) $settings->get( 'global.add_to_expire', 3600 ), 'number', 'min="0"' ),
			__( 'Each request from an already-blocked client extends its block by this much.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->render_proxy_section();
		$this->render_reliability_section();
		$this->render_sources_section();
		$this->render_bypass_section();

		$this->close_form();
	}

	/**
	 * The proxy question.
	 */
	private function render_proxy_section(): void {
		$settings   = $this->plugin()->settings();
		$configured = Trusted_Proxies::are_configured();

		printf( '<h2>%s</h2>', esc_html__( 'Proxies and the client IP', 'basic-firewall' ) );

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			esc_html__( 'Every rule that looks at an address depends on the client IP being trustworthy. A forwarding header is only honoured once trusted proxies have been established — and until they are, either every visitor appears to come from your proxy, or anyone can claim to be anyone.', 'basic-firewall' )
		);

		if ( ! $configured ) {
			$local = Trusted_Proxies::detect_local_stack();

			printf(
				'<div class="bfw-warning"><p><strong>%s</strong></p><p>%s</p><pre class="bfw-code">%s</pre></div>',
				esc_html__( 'No trusted proxies are configured.', 'basic-firewall' ),
				null !== $local
					? sprintf(
						/* translators: %s: detected local development stack. */
						esc_html__( '%s was detected. It routes every request through a router container, so PHP sees the router rather than your visitor — the same shape as production, and it is not configured for you.', 'basic-firewall' ),
						esc_html( $local['stack'] )
					)
					: esc_html__( 'Add the addresses of the proxies that front this site to wp-config.php. Narrow it to the proxy fleet: every address in the list is permitted to declare who the client is.', 'basic-firewall' ),
				esc_html( Site_Health::proxy_snippet( $local ) )
			);
		} else {
			printf(
				'<p><strong>%s</strong> <code>%s</code></p>',
				esc_html__( 'Trusted proxies:', 'basic-firewall' ),
				esc_html( implode( ', ', Trusted_Proxies::configured() ) )
			);
		}

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Is this site behind a proxy?', 'basic-firewall' ),
			self::select(
				'behind_proxy',
				array(
					'unknown' => __( 'Not stated — keep warning while this is unanswered', 'basic-firewall' ),
					'no'      => __( 'No — nothing proxies this site', 'basic-firewall' ),
					'yes'     => __( 'Yes — a proxy or CDN sits in front', 'basic-firewall' ),
				),
				(string) $settings->get( 'global.behind_proxy', 'unknown' )
			),
			__( 'Three answers, and the difference matters. <strong>Not stated</strong> is accurate and noisy: it is an open security question. <strong>No</strong> is silent, because nothing can forge a forwarding header through a proxy that does not exist — but if that is wrong, you have switched off the only signal that it was wrong. <strong>Yes</strong> escalates a missing trusted-proxy list from a warning to an error, because at that point the omission is a defect rather than an unknown.', 'basic-firewall' )
		);

		$this->row(
			__( 'Refuse to start without trusted proxies', 'basic-firewall' ),
			self::checkbox( 'require_trusted_proxies', (bool) $settings->get( 'global.require_trusted_proxies', false ), __( 'Do not run unless trusted proxies are configured', 'basic-firewall' ) ),
			__( 'The firewall fails open when it cannot start, so ticking this means a missing proxy configuration stops the firewall entirely rather than letting it evaluate a forgeable address. Right for a site that is definitely behind a CDN; wrong anywhere the answer varies by environment.', 'basic-firewall' )
		);

		echo '</tbody></table>';
	}

	/**
	 * Reliability settings.
	 */
	private function render_reliability_section(): void {
		printf( '<h2>%s</h2>', esc_html__( 'Reliability', 'basic-firewall' ) );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Report a configuration that fails to load', 'basic-firewall' ),
			self::checkbox(
				'require_config',
				(bool) $this->plugin()->settings()->get( 'global.require_config', true ),
				__( 'Treat a configuration that fails to load as a startup failure', 'basic-firewall' )
			),
			__( 'Leave this on. The firewall library loads configuration leniently: a file that is missing or malformed contributes nothing and it starts with whatever else parsed. Because this plugin compiles everything into one file, "whatever else parsed" is an empty rule set that allows every request — and looks exactly like a working firewall. With this on, the failure is reported instead. Traffic is treated the same either way; the difference is whether you find out.', 'basic-firewall' )
		);

		echo '</tbody></table>';
	}

	/**
	 * How often referenced lists are revalidated.
	 *
	 * The interval was in the settings schema from the start and had no field,
	 * which meant a site could reference a published list and have no way to
	 * say how often to re-read it -- and no way to see whether the last attempt
	 * had worked, which is the question that actually matters when an allow
	 * rule stops allowing.
	 */
	private function render_sources_section(): void {
		printf( '<h2>%s</h2>', esc_html__( 'Referenced lists', 'basic-firewall' ) );

		printf(
			'<p>%s</p>',
			wp_kses_post(
				__( 'A rule can name a published address list by URL instead of carrying a copy of it. Fetching never happens while a visitor waits — the request path reads a cached copy and nothing else, so an outage at the provider cannot become latency here — which makes this schedule the thing that keeps that copy current.', 'basic-firewall' )
			)
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Check for updates every', 'basic-firewall' ),
			self::select(
				'sources_cron_interval',
				array(
					(string) HOUR_IN_SECONDS         => __( 'Hour', 'basic-firewall' ),
					(string) ( 6 * HOUR_IN_SECONDS ) => __( '6 hours', 'basic-firewall' ),
					(string) DAY_IN_SECONDS          => __( 'Day (recommended)', 'basic-firewall' ),
					(string) WEEK_IN_SECONDS         => __( 'Week', 'basic-firewall' ),
					'0'                              => __( 'Never — I refresh them myself', 'basic-firewall' ),
				),
				(string) $this->plugin()->settings()->get( 'sources.cron_interval', DAY_IN_SECONDS )
			),
			wp_kses_post(
				__( 'This is how often WordPress <em>checks</em>; each list is only re-fetched once its own refresh interval has elapsed. Choose <strong>Never</strong> on a host where WP-Cron is disabled, and run <code>wp basic-firewall refresh-sources</code> from your own scheduler or deploy instead — a list that is never refreshed is not an error, and nothing will tell you it has gone stale.', 'basic-firewall' )
			)
		);

		$this->row( __( 'Last refresh', 'basic-firewall' ), '<p>' . wp_kses_post( $this->sources_status() ) . '</p>' );

		echo '</tbody></table>';
	}

	/**
	 * A sentence about the last refresh.
	 */
	private function sources_status(): string {
		$referenced = count( Refresher::declarations() );

		if ( 0 === $referenced ) {
			return esc_html__( 'No rule references a list, so nothing is being fetched.', 'basic-firewall' );
		}

		$last = Refresher::last_run();

		if ( array() === $last || empty( $last['at'] ) ) {
			return '<strong>' . esc_html__( 'Never.', 'basic-firewall' ) . '</strong> '
				. esc_html(
					sprintf(
						/* translators: %d: number of referenced lists. */
						_n(
							'%d list is referenced and has not been fetched yet. Until it is, the rule that references it matches only what is typed into it.',
							'%d lists are referenced and have not been fetched yet. Until they are, the rules that reference them match only what is typed into them.',
							$referenced,
							'basic-firewall'
						),
						$referenced
					)
				);
		}

		$when = sprintf(
			/* translators: %s: human-readable time difference. */
			esc_html__( '%s ago', 'basic-firewall' ),
			esc_html( human_time_diff( (int) $last['at'] ) )
		);

		$failed = (array) ( $last['failed'] ?? array() );

		if ( array() !== $failed ) {
			return '<strong>' . $when . '</strong> — '
				. esc_html(
					sprintf(
						/* translators: %s: comma-separated list names. */
						__( 'these could not be fetched: %s. Each list decides for itself what that means; the default keeps the last copy that worked.', 'basic-firewall' ),
						implode( ', ', array_keys( $failed ) )
					)
				);
		}

		$counts = array();

		foreach ( (array) ( $last['refreshed'] ?? array() ) as $name => $count ) {
			/* translators: 1: list name, 2: number of entries. */
			$counts[] = sprintf( esc_html__( '%1$s (%2$d entries)', 'basic-firewall' ), esc_html( (string) $name ), (int) $count );
		}

		return $when . ' — ' . ( array() === $counts ? esc_html__( 'nothing needed re-fetching.', 'basic-firewall' ) : implode( ', ', $counts ) );
	}

	/**
	 * Role exemptions.
	 */
	private function render_bypass_section(): void {
		$current = (array) $this->plugin()->settings()->get( 'global.bypass_roles', array() );

		printf( '<h2>%s</h2>', esc_html__( 'Exempt roles', 'basic-firewall' ) );

		printf(
			'<div class="bfw-warning"><p>%s</p></div>',
			esc_html__( 'Prefer something narrower where you can. An allow rule scoped to an office address range, or silencing the individual rule that misfires, both leave the rest of the firewall at full strength. A role exemption does not: anyone who can grant the role can exempt themselves, and an account takeover is unfiltered from that point on.', 'basic-firewall' )
		);

		echo '<table class="form-table" role="presentation"><tbody><tr><th scope="row">';
		echo esc_html__( 'Roles exempt from evaluation', 'basic-firewall' );
		echo '</th><td><fieldset>';

		foreach ( wp_roles()->get_names() as $role => $label ) {
			printf(
				'<label style="display:block"><input type="checkbox" name="bypass_roles[]" value="%s"%s /> %s</label>',
				esc_attr( $role ),
				checked( in_array( $role, $current, true ), true, false ),
				esc_html( translate_user_role( $label ) )
			);
		}

		echo '</fieldset><p class="description">';
		echo esc_html__( 'No rule runs for a member of an exempt role, and nothing is logged for them. Off by default: while this is empty the request path is identical to having no exemption feature at all.', 'basic-firewall' );
		echo '</p></td></tr></tbody></table>';
	}
}
