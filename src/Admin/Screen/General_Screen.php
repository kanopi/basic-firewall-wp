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
use Kanopi\BasicFirewall\Runtime\Lockdown;
use Kanopi\BasicFirewall\Runtime\Trusted_Proxies;
use Kanopi\BasicFirewall\Sources\Refresher;
use Kanopi\BasicFirewall\Support\Reverse_Dns;

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
		$all['global']['panic_file']              = $this->posted( 'panic_file' );
		$all['global']['lockdown']                = '' !== $this->posted( 'lockdown' );
		$all['global']['banning_json']            = '' !== $this->posted( 'banning_json' );

		$all['global']['block_page'] = array(
			'enabled' => '' !== $this->posted( 'block_page_enabled' ),
			'title'   => $this->posted( 'block_page_title' ),
			'heading' => $this->posted( 'block_page_heading' ),
		);

		$all['global']['lockdown_page'] = array(
			'enabled' => '' !== $this->posted( 'lockdown_page_enabled' ),
			'title'   => $this->posted( 'lockdown_page_title' ),
			'heading' => $this->posted( 'lockdown_page_heading' ),
			'message' => $this->posted_textarea( 'lockdown_page_message' ),
		);

		/*
		 * As typed: CSS is full of the characters the text sanitisers take
		 * out, and a stylesheet URL of the percent-encoded octets. Both are
		 * checked against the library's own rules when they are saved, and
		 * never printed unescaped.
		 */
		$all['global']['pages'] = array(
			'lang'       => $this->posted( 'pages_lang' ),
			'styles'     => $this->posted_typed_textarea( 'pages_styles' ),
			'stylesheet' => $this->posted_typed( 'pages_stylesheet' ),
		);

		$all['global']['reverse_dns'] = array(
			'provider'   => $this->posted( 'reverse_dns_provider' ),
			'timeout_ms' => $this->posted( 'reverse_dns_timeout_ms', (string) Reverse_Dns::DEFAULT_TIMEOUT_MS ),
		);

		$allow  = Lockdown::sort( $this->posted_textarea( 'lockdown_allow' ) );
		$review = Lockdown::review( $all['global']['lockdown'], $allow, Lockdown::client_address() );

		/*
		 * Refused outright rather than saved with a fallback, which is what
		 * every other field on this screen gets. A fallback here would be
		 * either an empty list -- the library's "serve nobody" -- or a list
		 * missing the entry somebody meant to be on it.
		 */
		if ( null !== $review['error'] ) {
			Notices::add( esc_html( $review['error'] ), 'error' );
			Notices::add( esc_html__( 'Nothing on this screen was saved.', 'basic-firewall' ), 'error' );

			$this->redirect( $this->slug() );
		}

		$all['global']['lockdown_allow'] = $allow['valid'];

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

		if ( null !== $review['warning'] ) {
			Notices::add( esc_html( $review['warning'] ), 'warning' );
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
			__( 'Available variables: <code>{{request.id}}</code> for the reference, which is what <code>wp basic-firewall find-reference</code> looks up, and <code>{{block.status}}</code> for the status sent. Keep it short and free of detail about why — a rejected client does not need to know which rule caught them, which is also why <code>{{block.rule}}</code>, the rule\'s name, is best left out. Sent as plain text, so HTML shows as source; for a page, switch on the block page below.', 'basic-firewall' )
		);

		$this->row(
			__( 'Status code for already-blocked clients', 'basic-firewall' ),
			self::text( 'repeat_offender_status', (string) $settings->get( 'global.repeat_offender_status', 403 ), 'number', 'min="100" max="599"' )
		);

		$this->row(
			__( 'Seconds added when a blocked client returns', 'basic-firewall' ),
			self::text( 'add_to_expire', (string) $settings->get( 'global.add_to_expire', 3600 ), 'number', 'min="1"' ),
			__( 'Each request from an already-blocked client extends its block by this much. The smallest is 1 second: the firewall library cannot be told to add nothing, and reads 0 as its default of 3600.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		$this->render_proxy_section();
		$this->render_reliability_section();
		$this->render_sources_section();
		$this->render_verification_section();
		$this->render_bypass_section();
		$this->render_lockdown_section();
		$this->render_pages_section();
		$this->render_panic_section();

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
	 * Who makes the DNS lookups behind crawler verification.
	 *
	 * Library 2.38.0 (kanopi/firewall#473). PHP's own lookups take no timeout,
	 * so on a host without a local caching resolver a slow nameserver holds a
	 * worker for up to ten seconds; a provider caps each lookup. The provider
	 * then receives visitors' addresses, written backwards, which is why the
	 * choice is the administrator's and the screen says so before they make it.
	 */
	private function render_verification_section(): void {
		$settings = $this->plugin()->settings();

		printf( '<h2 id="bfw-crawler-verification">%s</h2>', esc_html__( 'Crawler verification', 'basic-firewall' ) );

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			wp_kses_post( __( 'A user agent rule can verify that a client claiming to be Googlebot really is, by reverse DNS: look up the hostname its address claims, then confirm that hostname resolves back to it. These settings decide who makes those lookups, for every rule that verifies. They change nothing until a rule verifies.', 'basic-firewall' ) )
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Who makes the lookups', 'basic-firewall' ),
			self::select(
				'reverse_dns_provider',
				Reverse_Dns::choices( __( 'PHP\'s own lookups, through this host\'s resolver (default)', 'basic-firewall' ) ),
				(string) $settings->get( 'global.reverse_dns.provider', '' )
			),
			__( '<strong>PHP\'s own lookups</strong> send nothing to anyone, and are right for a host with a local caching resolver. They take no time limit: without such a resolver, one slow nameserver holds a PHP worker for up to ten seconds before the firewall stops verifying for a while.', 'basic-firewall' )
				. '<br><br>'
				. __( '<strong>A provider</strong> answers over HTTPS, and each lookup is cut off at the time limit below. <strong>Choosing one sends it the reverse-DNS name of each address a verifying rule asks about</strong> — the visitor\'s IP address, written backwards — and the hostname being confirmed. Only for requests that claim to be a crawler a rule verifies, and at most once per address an hour. Under the GDPR an IP address is personal data: read the provider\'s terms and privacy policy, and check your privacy notice covers it. Needs PHP\'s curl extension.', 'basic-firewall' )
				. '<br><br>'
				. __( 'To use a resolver you run, define it under <code>global.reverse_dns.providers</code> in the advanced YAML and name it with <code>provider</code> there.', 'basic-firewall' )
		);

		$this->row(
			__( 'Time limit per lookup', 'basic-firewall' ),
			self::text(
				'reverse_dns_timeout_ms',
				(string) $settings->get( 'global.reverse_dns.timeout_ms', Reverse_Dns::DEFAULT_TIMEOUT_MS ),
				'number',
				sprintf( 'min="1" max="%d"', Reverse_Dns::max_timeout_ms() )
			) . ' ' . esc_html__( 'milliseconds', 'basic-firewall' ),
			__( 'Applies to a provider only; PHP\'s own lookups cannot be given one. The limit includes connecting and the TLS handshake, so set it well above the provider\'s usual answer time, not just above it — measured upstream, a first verification costs 66–93 ms and later ones 19–40 ms. A verification makes up to three lookups. The default is 300.', 'basic-firewall' )
		);

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
	 * Lockdown.
	 *
	 * Near the end with the panic file, because both are levers for an
	 * incident rather than part of setting the firewall up.
	 */
	private function render_lockdown_section(): void {
		$settings = $this->plugin()->settings();
		$client   = Lockdown::client_address();

		printf( '<h2>%s</h2>', esc_html__( 'Lockdown', 'basic-firewall' ) );

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Lockdown', 'basic-firewall' ),
			self::checkbox( 'lockdown', (bool) $settings->get( 'global.lockdown', false ), __( 'Refuse everyone except the addresses below', 'basic-firewall' ) ),
			__( 'The "we are under attack, let only the office in" switch. Every other rule stops mattering: a client not on the list below is refused before any rule is consulted, and — unlike a block rule — <strong>nobody is recorded</strong>. That is the point. A block-everything rule would fill the block list with the entire internet during exactly the incident when your storage is under the most pressure, and leave every one of them banned once it was lifted.<br><br>Refused visitors get a 503 with <code>Retry-After</code>, which a CDN treats as temporary rather than caching as a verdict.', 'basic-firewall' )
		);

		$this->row(
			__( 'Addresses served during lockdown', 'basic-firewall' ),
			self::textarea( 'lockdown_allow', implode( "\n", Lockdown::lines( (array) $settings->get( 'global.lockdown_allow', array() ) ) ), 4 ),
			sprintf(
				/* translators: %s: the address the firewall sees for the current visitor. */
				__( 'One per line: single addresses, CIDR blocks and <code>start-end</code> ranges, IPv4 or IPv6 — the same forms an IP rule takes. It is consulted <em>instead of</em> your allow rules, not as well as them, and it is kept while lockdown is off so it is ready when you need it. The firewall sees your address as <code>%s</code>.', 'basic-firewall' ),
				esc_html( '' !== $client ? $client : __( 'unknown', 'basic-firewall' ) )
			)
		);

		echo '</tbody></table>';
	}

	/**
	 * The block and lockdown pages, and how every firewall page looks.
	 */
	private function render_pages_section(): void {
		$settings = $this->plugin()->settings();

		printf( '<h2>%s</h2>', esc_html__( 'Block and lockdown pages', 'basic-firewall' ) );

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			esc_html__( 'A refused visitor gets one line of plain text unless a page is switched on here. The page is the same card as the challenge page, sent with a strict Content-Security-Policy: no script, no form. Text is plain text with the same {{request.id}} placeholder as the message, and a field left empty keeps the built-in wording.', 'basic-firewall' )
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Block page', 'basic-firewall' ),
			self::checkbox( 'block_page_enabled', (bool) $settings->get( 'global.block_page.enabled', false ), __( 'Show blocked clients a page instead of the message', 'basic-firewall' ) ),
			__( 'The page\'s text is the <strong>Message shown to blocked clients</strong> above, one paragraph per line.', 'basic-firewall' )
		);

		$this->row(
			__( 'Block page title', 'basic-firewall' ),
			self::text( 'block_page_title', (string) $settings->get( 'global.block_page.title', '' ), 'text', 'placeholder="Request blocked"' )
		);

		$this->row(
			__( 'Block page heading', 'basic-firewall' ),
			self::text( 'block_page_heading', (string) $settings->get( 'global.block_page.heading', '' ), 'text', 'placeholder="Request blocked"' )
		);

		$this->row(
			__( 'Lockdown page', 'basic-firewall' ),
			self::checkbox( 'lockdown_page_enabled', (bool) $settings->get( 'global.lockdown_page.enabled', false ), __( 'Show visitors refused by lockdown a page', 'basic-firewall' ) )
		);

		$this->row(
			__( 'Lockdown page title', 'basic-firewall' ),
			self::text( 'lockdown_page_title', (string) $settings->get( 'global.lockdown_page.title', '' ), 'text', 'placeholder="Temporarily closed"' )
		);

		$this->row(
			__( 'Lockdown page heading', 'basic-firewall' ),
			self::text( 'lockdown_page_heading', (string) $settings->get( 'global.lockdown_page.heading', '' ), 'text', 'placeholder="Temporarily closed"' )
		);

		$this->row(
			__( 'Lockdown page message', 'basic-firewall' ),
			self::textarea( 'lockdown_page_message', (string) $settings->get( 'global.lockdown_page.message', '' ), 3 ),
			__( 'One paragraph per line. Empty: "This site is temporarily closed to visitors. Please try again shortly."', 'basic-firewall' )
		);

		$this->row(
			__( 'JSON for API clients', 'basic-firewall' ),
			self::checkbox( 'banning_json', (bool) $settings->get( 'global.banning_json', false ), __( 'Answer a client that asks for JSON with JSON', 'basic-firewall' ) ),
			__( 'A client whose first preference is JSON — the REST API\'s, a mobile app\'s — gets <code>{"error":"blocked","status":403,"request_id":"…"}</code> instead of the page or the message. A browser asks for HTML first and is unaffected.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		printf( '<h2 id="bfw-page-appearance">%s</h2>', esc_html__( 'Page appearance', 'basic-firewall' ) );

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			wp_kses_post( __( 'Applies to the challenge, block and lockdown pages alike. Every colour on them is a CSS custom property, so <code>:root { --fw-accent: #0b8f5a; --fw-accent-hover: #087448; }</code> recolours the button on all three. The others are <code>--fw-bg</code>, <code>--fw-text</code>, <code>--fw-card</code>, <code>--fw-muted</code>, <code>--fw-accent-text</code>, <code>--fw-accent-disabled</code> and <code>--fw-error</code>.', 'basic-firewall' ) )
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Language', 'basic-firewall' ),
			self::text( 'pages_lang', (string) $settings->get( 'global.pages.lang', '' ), 'text', 'placeholder="en"' ),
			__( 'The pages\' <code>lang</code> attribute: a language tag such as <code>en</code> or <code>fr-CA</code>. Set it when you translate the wording, so a screen reader pronounces it correctly.', 'basic-firewall' )
		);

		$this->row(
			__( 'CSS', 'basic-firewall' ),
			self::textarea( 'pages_styles', (string) $settings->get( 'global.pages.styles', '' ), 4 ),
			__( 'Added after the built-in rules, so yours win. A logo goes here as a <code>background-image</code>.', 'basic-firewall' )
		);

		$this->row(
			__( 'Stylesheet', 'basic-firewall' ),
			self::text( 'pages_stylesheet', (string) $settings->get( 'global.pages.stylesheet', '' ), 'text', 'placeholder="/wp-content/themes/your-theme/firewall.css"' ),
			__( 'A path on this site or an <code>https:</code> URL, linked after the built-in CSS.', 'basic-firewall' )
		);

		echo '</tbody></table>';
	}

	/**
	 * The panic file.
	 *
	 * Last on the screen, deliberately. It is the lever for an incident, not
	 * part of setting the firewall up, and a section headed "Panic" sitting
	 * among the everyday settings read as though it wanted something doing.
	 */
	private function render_panic_section(): void {
		$current = (string) $this->plugin()->settings()->get( 'global.panic_file', '' );

		printf( '<h2>%s</h2>', esc_html__( 'Panic file', 'basic-firewall' ) );

		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			printf(
				'<div class="bfw-warning"><p>%s</p></div>',
				esc_html__( 'BASIC_FIREWALL_MODE is set in wp-config.php, and it wins over the panic file as well: an environment that pins its mode keeps it pinned. The file below is ignored while the constant is defined.', 'basic-firewall' )
			);
		}

		echo '<table class="form-table" role="presentation"><tbody>';

		$description = __( 'A path the firewall checks on every request. Writing a mode name into that file changes the operating mode immediately, with no deploy, no cache clear and no restart — which is what you want when a rule is blocking real customers and the fix is otherwise gated behind a release. Leave empty to arm nothing; the check costs nothing while it is unset.', 'basic-firewall' )
			. '<br><br>'
			. __( 'A relative path resolves inside the firewall\'s private directory, which is guarded against web access. Keep it out of anything a deploy recreates: a file that turns the firewall down is worth exactly as much as write access to where it lives.', 'basic-firewall' );

		if ( '' !== trim( $current ) ) {
			$description .= '<br><br>' . sprintf(
				/* translators: %s: absolute file path. */
				__( 'Currently checked at %s', 'basic-firewall' ),
				'<code>' . esc_html( $this->plugin()->paths()->resolve( $current ) ) . '</code>'
			);
		}

		$this->row(
			__( 'Panic file', 'basic-firewall' ),
			self::text( 'panic_file', $current ),
			$description
		);

		echo '</tbody></table>';

		printf(
			'<p style="max-width:48rem">%s</p><pre class="bfw-code">%s</pre><p style="max-width:48rem">%s</p>',
			wp_kses_post( __( 'The file has to <em>name</em> a mode, one of <code>block</code>, <code>log</code>, <code>exception</code>, <code>disabled</code> or <code>lockdown</code> — the last refusing everyone but the lockdown allowlist above, so fill that in first:', 'basic-firewall' ) ),
			esc_html( "echo log > PATH   # stop enforcing, keep recording\nrm PATH            # back to the configured mode" ),
			wp_kses_post( __( 'An empty file, a typo or one that cannot be read changes <strong>nothing</strong>, and Site Health reports it. That is deliberate: if any file at all meant "off", one left behind from last month would disable the firewall and nobody would know. While a file is active, Site Health raises it as critical, the Status screen leads with it, and <code>wp basic-firewall status</code> reports it.', 'basic-firewall' ) )
		);
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
		echo ' ';
		echo esc_html__( 'Roles are not known where the firewall runs — before WordPress has checked anybody\'s login — so once a role is exempt, a request carrying a WordPress login cookie is evaluated after plugins load, when the cookie can be checked, on both evaluation paths. A cookie that does not check out is evaluated like any other request, just later. A page cache that serves pages to logged-in visitors would serve those requests before the firewall sees them; the common ones do not by default.', 'basic-firewall' );
		echo '</p></td></tr></tbody></table>';
	}
}
