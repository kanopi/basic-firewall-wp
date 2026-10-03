<?php
/**
 * Challenge settings.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin\Screen;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Notices;
use Kanopi\BasicFirewall\Admin\Screen;
use Kanopi\BasicFirewall\Challenge\Pass_Cookie;
use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Install\Challenge_Secret;
use Kanopi\BasicFirewall\Support\Page_Settings;

/**
 * The interstitial a challenged visitor solves.
 */
final class Challenge_Screen extends Screen {

	/**
	 * {@inheritDoc}
	 */
	public function slug(): string {
		return 'basic-firewall-challenge';
	}

	/**
	 * {@inheritDoc}
	 */
	public function page_title(): string {
		return __( 'Challenge', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function intro(): string {
		return esc_html__( 'A rule set to Challenge serves a short interstitial instead of rejecting the request. A visitor who solves it gets a signed pass token and is not challenged again until it expires. It slows automated traffic without shutting people out. A pass token proves only that its holder solved a challenge — it does not exempt them from block rules, which still run afterwards.', 'basic-firewall' );
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

		$provider = $this->posted( 'provider', 'math' );

		$all['challenge']['provider']    = $provider;
		$all['challenge']['path']        = $this->posted( 'path' );
		$all['challenge']['cookie_name'] = $this->posted( 'cookie_name' );
		$all['challenge']['header_name'] = $this->posted( 'header_name' );
		$all['challenge']['audience']    = $this->posted( 'audience' );
		$all['challenge']['ttl']         = (int) $this->posted( 'ttl', '3600' );

		foreach ( Page_Settings::CHALLENGE_TEXT_KEYS as $key ) {
			$all['challenge']['page'][ $key ] = $this->posted( 'page_' . $key );
		}

		/*
		 * As typed, like the shared appearance on the General screen: CSS is
		 * full of what the text sanitisers take out. Each is checked against
		 * the library's own rules on save.
		 */
		$all['challenge']['page']['lang']       = $this->posted( 'page_lang' );
		$all['challenge']['page']['styles']     = $this->posted_typed_textarea( 'page_styles' );
		$all['challenge']['page']['stylesheet'] = $this->posted_typed( 'page_stylesheet' );

		$all['challenge']['notice'] = array_values(
			array_filter(
				array_map( 'trim', (array) preg_split( '/\R/', $this->posted_textarea( 'notice' ) ) ),
				static fn ( string $line ): bool => '' !== $line
			)
		);

		$secret = $this->posted( 'secret' );

		// Empty means "not carried", never "clear it". Clearing the secret stops
		// the firewall starting at all, which fails open.
		if ( '' !== $secret ) {
			$all['challenge']['secret'] = $secret;
		}

		$options = $this->posted_array( 'options' );

		foreach ( array( 'altcha', 'turnstile', 'recaptcha' ) as $name ) {
			$incoming = (array) ( $options[ $name ] ?? array() );

			foreach ( $incoming as $key => $value ) {
				// Same rule for the provider secret keys.
				if ( 'secret_key' === $key && '' === trim( (string) $value ) ) {
					continue;
				}

				$all['challenge']['provider_options'][ $name ][ $key ] = $value;
			}

			// Checkboxes only post when ticked.
			foreach ( array( 'send_remoteip', 'use_recaptcha_net' ) as $flag ) {
				if ( isset( $all['challenge']['provider_options'][ $name ][ $flag ] ) ) {
					$all['challenge']['provider_options'][ $name ][ $flag ] = isset( $incoming[ $flag ] );
				}
			}
		}

		/*
		 * The pass cookie name is required, like a remote provider's keys: an
		 * empty or malformed name is refused rather than quietly replaced, so
		 * the field always shows the cookie actually in use.
		 */
		if ( ! Pass_Cookie::is_valid( (string) $all['challenge']['cookie_name'] ) ) {
			Notices::add(
				__( 'The pass token cookie needs a name made of letters, digits and !#$%&\'*+-.^_`|~ only — no spaces, commas, semicolons or equals signs. Nothing was saved.', 'basic-firewall' ),
				'error'
			);

			$this->redirect( $this->slug() );
		}

		/*
		 * A remote provider without both keys is refused at save time rather
		 * than at request time. The library raises during startup, this plugin
		 * catches it and fails open, and the result is a site with no firewall
		 * running at all -- not one broken challenge.
		 */
		if ( in_array( $provider, Library_Map::REMOTE_CHALLENGE_PROVIDERS, true ) ) {
			$keys = $all['challenge']['provider_options'][ $provider ] ?? array();

			if ( '' === trim( (string) ( $keys['site_key'] ?? '' ) ) || '' === trim( (string) ( $keys['secret_key'] ?? '' ) ) ) {
				Notices::add(
					__( 'That provider needs both a site key and a secret key. Without them the firewall refuses to start — which would leave this site with no firewall running at all, not just a broken challenge. Nothing was saved.', 'basic-firewall' ),
					'error'
				);

				$this->redirect( $this->slug() );
			}
		}

		$problems = $settings->replace( $all );

		foreach ( $problems as $problem ) {
			Notices::add( sprintf( '<strong>%s</strong>: %s', esc_html( $problem['path'] ), esc_html( $problem['message'] ) ), 'error' );
		}

		if ( array() === $problems ) {
			Notices::add( __( 'Challenge settings saved, and the firewall recompiled.', 'basic-firewall' ) );
		}

		$this->redirect( $this->slug() );
	}

	/**
	 * {@inheritDoc}
	 */
	public function render(): void {
		$settings = $this->plugin()->settings();
		$provider = (string) $settings->get( 'challenge.provider', 'math' );

		$this->open_form();

		echo '<table class="form-table" role="presentation"><tbody>';

		$this->row(
			__( 'Provider', 'basic-firewall' ),
			self::select( 'provider', Library_Map::CHALLENGE_PROVIDERS, $provider ),
			__( 'The first two run entirely on this site: no account, no third party, nothing leaves. The last two are verified by Cloudflare or Google — stronger bot detection, in exchange for an account, a key pair, an outbound request while the visitor waits, and the visitor\'s browser contacting another origin.', 'basic-firewall' )
		);

		$this->render_secret_row();

		$this->row(
			__( 'Token audience', 'basic-firewall' ),
			self::text( 'audience', (string) $settings->get( 'challenge.audience', '' ) ),
			__( 'Only needed if several sites share one signing secret. A token attests that its holder solved <em>some</em> challenge, so without an audience a token earned against an easy challenge is accepted where a harder one is expected — and the weakest challenge sets the strength of them all.', 'basic-firewall' )
		);

		$this->row(
			__( 'A solved challenge lasts', 'basic-firewall' ),
			self::text( 'ttl', (string) $settings->get( 'challenge.ttl', 3600 ), 'number', 'min="60" max="2592000"' ) . ' ' . esc_html__( 'seconds', 'basic-firewall' ),
			wp_kses_post(
				__( 'A <strong>ceiling as well as a default</strong>. A challenge rule asking for longer than this is granted this instead, quietly — so if a rule\'s expiry looks like it is being ignored, this is why.<br><br>It is a ceiling because the lifetime used to arrive in the interstitial\'s own form: solve one puzzle, ask for thirty-one years, and hold a signed exemption from every challenge rule for three decades. An hour suits a visitor who hit a rule once; raise it for a rule people trip over repeatedly, and weigh that against how long a pass earned by a script stays good.', 'basic-firewall' )
			)
		);

		$this->row(
			__( 'Challenge path', 'basic-firewall' ),
			self::text( 'path', (string) $settings->get( 'challenge.path', '' ) ),
			__( 'Where the interstitial posts its answer. It must not collide with a real route on this site.', 'basic-firewall' )
		);

		$this->row(
			__( 'Pass token cookie', 'basic-firewall' ),
			self::text( 'cookie_name', (string) $settings->get( 'challenge.cookie_name', '' ) ),
			__( 'The cookie a solved challenge is remembered in. Some hosts and edge caches only pass on cookies whose names match their own rules; if visitors are challenged again straight after solving one, set a name your host forwards. Changing it invalidates passes already issued, so each visitor holding one is challenged once more.', 'basic-firewall' )
		);

		$this->row(
			__( 'Pass token header', 'basic-firewall' ),
			self::text( 'header_name', (string) $settings->get( 'challenge.header_name', '' ) ),
			__( 'For API clients that cannot hold a cookie.', 'basic-firewall' )
		);

		echo '</tbody></table>';

		/*
		 * Every provider's settings, shown by condition on the select above.
		 *
		 * Only the saved provider's section used to render, which made the
		 * settings unreachable at the one moment somebody wants them: pick
		 * Google reCAPTCHA, and nothing appears -- no keys, and no way to say
		 * whether you want the checkbox or the invisible scoring one -- until
		 * the form has been saved and reloaded. Choosing a provider and
		 * configuring it is one decision, so it is one screenful.
		 */
		foreach ( array_keys( Library_Map::CHALLENGE_PROVIDERS ) as $name ) {
			printf( '<div data-bfw-show-when="provider:%s">', esc_attr( (string) $name ) );

			$this->render_provider_options( (string) $name );

			echo '</div>';
		}

		$this->render_page_section();

		$this->close_form();
	}

	/**
	 * The interstitial's own wording.
	 *
	 * Every field left empty keeps the firewall's built-in wording, which is
	 * shown as the placeholder so an empty field still says what visitors
	 * read. Language and colours are on the General screen, because the block
	 * and lockdown pages share them.
	 */
	private function render_page_section(): void {
		$settings = $this->plugin()->settings();

		printf( '<h2>%s</h2>', esc_html__( 'Challenge page', 'basic-firewall' ) );

		printf(
			'<p class="description" style="max-width:48rem">%s</p>',
			wp_kses_post(
				sprintf(
					/* translators: %s: URL of the General settings screen. */
					__( 'What a visitor asked to verify reads, and how the page looks. Text is plain text; leave a field empty for the built-in wording. Language, CSS and a stylesheet set under <a href="%s">Page appearance</a> on the General screen apply here too, shared with the block and lockdown pages: CSS below is added after that, and a language or stylesheet below replaces it, for this page only. The widget\'s own text, such as Turnstile\'s, comes from the widget.', 'basic-firewall' ),
					esc_url( Admin::url( 'basic-firewall-general' ) . '#bfw-page-appearance' )
				)
			)
		);

		echo '<table class="form-table" role="presentation"><tbody>';

		$fields = array(
			'title'         => array( __( 'Browser tab title', 'basic-firewall' ), 'Verification required' ),
			'heading'       => array( __( 'Heading', 'basic-firewall' ), 'Quick verification' ),
			'intro'         => array( __( 'Line under the heading', 'basic-firewall' ), __( 'The provider\'s own', 'basic-firewall' ) ),
			'button'        => array( __( 'Button label', 'basic-firewall' ), 'Continue' ),
			'error_message' => array( __( 'Shown when a submission is refused', 'basic-firewall' ), __( 'The provider\'s own', 'basic-firewall' ) ),
		);

		foreach ( $fields as $key => $field ) {
			$this->row(
				$field[0],
				self::text( 'page_' . $key, (string) $settings->get( 'challenge.page.' . $key, '' ), 'text', sprintf( 'placeholder="%s"', esc_attr( $field[1] ) ) )
			);
		}

		$this->row(
			__( 'Notices', 'basic-firewall' ),
			self::textarea( 'notice', implode( "\n", (array) $settings->get( 'challenge.notice', array() ) ), 3 ),
			__( 'One per line, each shown in its own box above the form on every challenge page: a help address, or why visitors are being asked. Plain text.', 'basic-firewall' )
		);

		$this->row(
			__( 'Language', 'basic-firewall' ),
			self::text( 'page_lang', (string) $settings->get( 'challenge.page.lang', '' ), 'text', 'placeholder="en"' ),
			__( 'The page\'s <code>lang</code> attribute, such as <code>fr-CA</code>. Empty uses Page appearance\'s, or <code>en</code>.', 'basic-firewall' )
		);

		$this->row(
			__( 'CSS', 'basic-firewall' ),
			self::textarea( 'page_styles', (string) $settings->get( 'challenge.page.styles', '' ), 6 ),
			__( 'Added after the built-in rules and the shared CSS, so yours win. Every colour is a custom property: <code>--fw-bg</code>, <code>--fw-text</code>, <code>--fw-card</code>, <code>--fw-card-shadow</code>, <code>--fw-muted</code>, <code>--fw-accent</code>, <code>--fw-accent-hover</code>, <code>--fw-accent-disabled</code>, <code>--fw-accent-text</code>, <code>--fw-error</code>, <code>--fw-notice-bg</code>, <code>--fw-notice-border</code>, <code>--fw-notice-text</code> and <code>--fw-input-border</code> (the math answer box). For example <code>:root { --fw-accent: #0b8f5a; }</code>. A logo goes here as a <code>background-image</code>.', 'basic-firewall' )
		);

		$this->row(
			__( 'Stylesheet', 'basic-firewall' ),
			self::text( 'page_stylesheet', (string) $settings->get( 'challenge.page.stylesheet', '' ), 'text', 'placeholder="/wp-content/themes/your-theme/challenge.css"' ),
			__( 'A path on this site or an <code>https:</code> URL, linked after the built-in CSS. Empty uses Page appearance\'s.', 'basic-firewall' )
		);

		echo '</tbody></table>';
	}

	/**
	 * The signing secret row, which has three states.
	 */
	private function render_secret_row(): void {
		if ( Challenge_Secret::is_overridden() ) {
			/*
			 * Shown as disabled rather than hidden or blank: the interface must
			 * never display a value that is not the one being used.
			 */
			$this->row(
				__( 'Signing secret', 'basic-firewall' ),
				'<input type="text" class="regular-text" value="" placeholder="' . esc_attr__( 'set in wp-config.php', 'basic-firewall' ) . '" disabled />',
				sprintf(
					/* translators: %s: constant name. */
					__( 'Supplied by the <code>%s</code> constant in wp-config.php, which takes precedence over anything stored here. This field is disabled so the screen cannot show a value that is not the one in force.', 'basic-firewall' ),
					esc_html( Challenge_Secret::CONSTANT )
				)
			);

			return;
		}

		$stored = (string) $this->plugin()->settings()->get( 'challenge.secret', '' );

		$this->row(
			__( 'Signing secret', 'basic-firewall' ),
			self::text( 'secret', '', 'text', 'placeholder="' . esc_attr( '' === $stored ? __( 'not set', 'basic-firewall' ) : __( 'stored — leave blank to keep it', 'basic-firewall' ) ) . '"' ),
			/* translators: %s: the value described in the sentence. */
			__( 'Signs the pass tokens, so one cannot be forged. Generated automatically when the plugin is activated; you do not normally touch this. <strong>Leaving it blank keeps the stored value</strong> — it is never cleared by saving, because a firewall that cannot sign a token refuses to start, and this plugin then fails open. To keep it out of a database export, put an <code>%env(NAME)%</code> token here, or set the constant in wp-config.php. Replacing it invalidates every token already issued, so anyone part-way through a challenge is asked to solve another.', 'basic-firewall' )
		);
	}

	/**
	 * Options for the chosen provider only.
	 *
	 * Only the chosen one: three of the four accept a widget URL, and showing
	 * them all invites somebody to fill in the wrong one.
	 *
	 * @param string $provider Chosen provider.
	 */
	private function render_provider_options( string $provider ): void {
		if ( 'math' === $provider ) {
			printf(
				'<p class="description">%s</p>',
				esc_html__( 'The arithmetic challenge has nothing to configure: one addition, no JavaScript, no external script, no account.', 'basic-firewall' )
			);

			return;
		}

		$settings = $this->plugin()->settings();
		$options  = (array) $settings->get( 'challenge.provider_options.' . $provider, array() );

		printf( '<h2>%s</h2>', esc_html( Library_Map::CHALLENGE_PROVIDERS[ $provider ] ?? $provider ) );

		echo '<table class="form-table" role="presentation"><tbody>';

		if ( 'altcha' === $provider ) {
			$this->row(
				__( 'Widget script URL', 'basic-firewall' ),
				self::text( 'options[altcha][widget_src]', (string) ( $options['widget_src'] ?? '' ) ),
				__( 'Where the visitor\'s browser loads the ALTCHA widget from. Self-host it if you would rather the challenge involved no third party at all.', 'basic-firewall' )
			);

			$this->row(
				__( 'Subresource Integrity digest', 'basic-firewall' ),
				self::text( 'options[altcha][widget_integrity]', (string) ( $options['widget_integrity'] ?? '' ) ),
				__( 'Pins the script to a known hash, so a compromised CDN cannot serve different code to your challenged visitors.', 'basic-firewall' )
			);

			echo '</tbody></table>';

			return;
		}

		$this->row(
			__( 'Site key', 'basic-firewall' ),
			self::text( 'options[' . $provider . '][site_key]', (string) ( $options['site_key'] ?? '' ) ),
			__( 'Public — it appears in the page source, so it needs no special handling and is not stripped from exports.', 'basic-firewall' )
		);

		$this->row(
			__( 'Secret key', 'basic-firewall' ),
			self::text( 'options[' . $provider . '][secret_key]', '', 'text', 'placeholder="' . esc_attr( '' === (string) ( $options['secret_key'] ?? '' ) ? __( 'not set', 'basic-firewall' ) : __( 'stored — leave blank to keep it', 'basic-firewall' ) ) . '"' ),
			/* translators: %s: the value described in the sentence. */
			__( 'A credential. Prefer <code>%env(NAME)%</code> over the key itself: exports strip a literal value and say so, and a rotated value is picked up without a rebuild. Leaving this blank keeps what is stored.', 'basic-firewall' )
		);

		if ( 'recaptcha' === $provider ) {
			$this->row(
				__( 'Version', 'basic-firewall' ),
				self::select(
					'options[recaptcha][version]',
					array(
						'v2' => __( 'v2 — the "I\'m not a robot" checkbox', 'basic-firewall' ),
						'v3' => __( 'v3 — invisible, returns a score', 'basic-firewall' ),
					),
					(string) ( $options['version'] ?? 'v2' )
				),
				__( '<strong>Prefer v2 unless you have a reason not to.</strong> v3 never asks the visitor for anything, which sounds strictly better and is not: a real person who scores below your threshold has no puzzle to solve and no retry that helps. On a route people actually need, that is a lockout with no way out.', 'basic-firewall' )
			);

			/*
			 * The version decides which of the rest apply, so it decides which
			 * are shown. Four options labelled "(v2 only)" and "(v3 only)" in a
			 * flat list is a reader working out which half to ignore.
			 */
			$this->row(
				__( 'Widget appearance', 'basic-firewall' ),
				self::select(
					'options[recaptcha][theme]',
					array(
						'light' => __( 'Light', 'basic-firewall' ),
						'dark'  => __( 'Dark', 'basic-firewall' ),
					),
					(string) ( $options['theme'] ?? 'light' )
				)
				. ' ' . self::select(
					'options[recaptcha][size]',
					array(
						'normal'  => __( 'Normal', 'basic-firewall' ),
						'compact' => __( 'Compact', 'basic-firewall' ),
					),
					(string) ( $options['size'] ?? 'normal' )
				),
				esc_html__( 'How the checkbox looks on the interstitial. The firewall\'s page is plain, so light and normal suit it; dark and compact are there for a site where they do not.', 'basic-firewall' ),
				'options[recaptcha][version]:v2'
			);

			$this->row(
				__( 'Minimum score', 'basic-firewall' ),
				self::text( 'options[recaptcha][min_score]', (string) ( $options['min_score'] ?? 0.5 ), 'number', 'min="0" max="1" step="0.05"' ),
				esc_html__( 'Pick this from your own traffic rather than from the 0.5 in Google\'s documentation. Anyone scoring below it is refused with no puzzle to solve.', 'basic-firewall' ),
				'options[recaptcha][version]:v3'
			);

			$this->row(
				__( 'Action name', 'basic-firewall' ),
				self::text( 'options[recaptcha][action]', (string) ( $options['action'] ?? 'firewall' ) ),
				esc_html__( 'Minted into the token and required back unchanged. A v3 token comes from the site key rather than from any particular page, so without this check a token produced by any other reCAPTCHA v3 call on your site — a search box, a newsletter signup — would satisfy the firewall challenge too.', 'basic-firewall' ),
				'options[recaptcha][version]:v3'
			);
		}

		$this->row(
			__( 'Verification timeout', 'basic-firewall' ),
			self::text( 'options[' . $provider . '][timeout]', (string) ( $options['timeout'] ?? 5 ), 'number', 'min="1" max="' . Library_Map::CHALLENGE_TIMEOUT_MAX . '"' ),
			sprintf(
				/* translators: %d: the longest timeout the provider allows. */
				__( 'Seconds, up to %d — the most the provider will wait, whatever is asked for. The visitor is waiting for this.', 'basic-firewall' ),
				Library_Map::CHALLENGE_TIMEOUT_MAX
			)
		);

		$this->row(
			__( 'If verification cannot be reached', 'basic-firewall' ),
			self::select(
				'options[' . $provider . '][on_error]',
				array(
					'fail' => __( 'Reject the visitor', 'basic-firewall' ),
					'pass' => __( 'Let the visitor through unverified', 'basic-firewall' ),
				),
				(string) ( $options['on_error'] ?? 'fail' )
			),
			__( 'The default rejects. Letting them through means an outage at the vendor — or anything blocking outbound requests from your server — switches the challenge off instead of taking the page down. While it lasts, every visitor passes unverified.', 'basic-firewall' )
		);

		$this->row(
			__( 'Send the visitor\'s IP address', 'basic-firewall' ),
			self::checkbox( 'options[' . $provider . '][send_remoteip]', ! empty( $options['send_remoteip'] ), __( 'Forward the client IP to the vendor', 'basic-firewall' ) ),
			__( 'Off by default. It discloses every challenged visitor\'s address to the vendor, and a mismatch between the address you send and the one they observe can make verification fail rather than improve it.', 'basic-firewall' )
		);

		echo '</tbody></table>';
	}
}
