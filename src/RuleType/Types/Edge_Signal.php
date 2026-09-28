<?php
/**
 * The edge signal rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Response_Settings;
use Kanopi\Firewall\Plugins\EdgeSignal;

/**
 * Matches on what the CDN worked out that this site cannot.
 *
 * Two kinds of signal, and they are worth different things. A **TLS
 * fingerprint** -- `ja3`, `ja4` -- identifies the client stack rather than what
 * it claims to be, so a script wearing a browser's user agent still negotiates
 * TLS like a script. A **bot score** is the edge's own verdict, from signals
 * that never reach the origin at all. Neither can be computed here, which is
 * the whole reason for the type: the edge already decided, and this reads the
 * decision.
 *
 * Two things about it are worth knowing before writing a rule, and the screen
 * says both where the CDN is chosen:
 *
 * - **An edge header is a claim.** Anything that can reach the site directly
 *   can send `Cf-Bot-Score: 99`, so the library believes these headers only on
 *   a request that arrived through a trusted proxy. Without trusted proxies the
 *   rule matches nothing -- and that looks exactly like a quiet day.
 * - **Cloudflare's score runs backwards.** 1 is certainly a bot and 99 certainly
 *   a human, the opposite of every other score in the firewall, so the rule
 *   that blocks bots is `bot_score` *at most* 5. Written the habitual way round
 *   on a block rule, it blocks the humans and lets the automation through, and
 *   it looks like it is working.
 */
final class Edge_Signal extends Condition_Rule_Type_Base {

	/**
	 * CDNs whose edge headers the library knows the names of.
	 *
	 * Mirrors `EdgeSignalMap::PROVIDERS`, held here rather than read from the
	 * class so the screen still renders against a library that predates it.
	 * Three and no more, because upstream declined to guess: Akamai Bot
	 * Manager's headers are configured per property, and CloudFront computes no
	 * bot signal at all. Both are reachable through "something else", which is
	 * the honest answer -- a named profile with invented header names would look
	 * authoritative and match nothing.
	 */
	public const PROVIDERS = array( 'cloudflare', 'fastly', 'custom' );

	/**
	 * The signals a header mapping may name.
	 *
	 * Mirrors `EdgeSignalMap::FIELDS`. An unknown one is a configuration error
	 * when the library starts, and a firewall that cannot start fails open on
	 * every rule, not just this one -- so it is caught on the screen instead.
	 */
	public const FIELDS = array( 'bot_score', 'verified_bot', 'ja3', 'ja4' );

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'edge_signal';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'Edge signal', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches on a TLS fingerprint or the bot score your CDN computed. Both describe the client itself rather than what it claims to be, and neither can be worked out here. Needs a CDN in front of the site, sending the headers, and trusted proxies configured.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return EdgeSignal::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -35;
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variable_options(): array {
		return array(
			'bot_score'    => __( 'Bot score the edge computed. On Cloudflare 1 is certainly a bot and 99 certainly a human.', 'basic-firewall' ),
			'verified_bot' => __( 'Whether the edge verified the bot as who it claims to be', 'basic-firewall' ),
			'ja3'          => __( 'JA3 TLS fingerprint', 'basic-firewall' ),
			'ja4'          => __( 'JA4 TLS fingerprint', 'basic-firewall' ),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return parent::default_settings() + array(
			'provider'       => 'cloudflare',

			/*
			 * One "signal: Header-Name" per line, and read only for a custom
			 * CDN. Kept when the CDN is switched, so switching back does not
			 * lose what was typed.
			 */
			'custom_headers' => array(),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function settings_help(): array {
		return array(
			'provider'       => array(
				'label'       => __( 'CDN', 'basic-firewall' ),
				'choices'     => array(
					'cloudflare' => __( 'Cloudflare — the headers need Managed Transforms switched on per zone', 'basic-firewall' ),
					'fastly'     => __( 'Fastly — set the headers in VCL', 'basic-firewall' ),
					'custom'     => __( 'Something else — name the headers yourself', 'basic-firewall' ),
				),
				'description' => __( '<strong>An edge header is a claim, not a fact.</strong> Anything that can reach this site directly can send <code>Cf-Bot-Score: 99</code> and call itself human, so the firewall believes these headers only on a request that arrived through a trusted proxy — answer the proxy question on the General screen and configure your trusted proxies, which a site behind a CDN needs anyway for the client address to be right. Without that this rule matches nothing, and says so in the log on every request.<br><br>None of these headers arrive without being asked for. A header the edge did not send matches nothing rather than matching wrongly, so a rule that quietly never matches usually means the Managed Transform or the VCL snippet is missing.<br><br><strong>Cloudflare\'s bot score runs backwards.</strong> On Cloudflare, <strong>1 means certainly a bot and 99 means certainly a human</strong> — the opposite of every other score here. A rule that blocks bots is <code>bot_score</code> <em>is less than or equal to</em> <code>5</code>. Writing <code>bot_score</code> <em>is greater than</em> <code>30</code> on a blocking rule blocks the humans instead, and it will look like it is working: what it lets through is the automated traffic. Try it with <strong>Observe only</strong> first.', 'basic-firewall' ),
			),
			'custom_headers' => array(
				'label'       => __( 'Header names', 'basic-firewall' ),
				'description' => sprintf(
					/* translators: %s: the signal names. */
					__( 'One <code>signal: Header-Name</code> per line, for example <code>bot_score: X-Edge-Bot-Score</code>. The signals are %s.', 'basic-firewall' ),
					'<code>' . implode( '</code>, <code>', self::FIELDS ) . '</code>'
				),
				'show_when'   => 'settings[provider]:custom',
			),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed>  $settings Described by the interface.
	 * @param array<string, string> $errors Described by the interface.
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$clean = parent::validate_settings( $settings, $errors );

		$provider = (string) ( $settings['provider'] ?? 'cloudflare' );

		$clean['provider']       = in_array( $provider, self::PROVIDERS, true ) ? $provider : 'cloudflare';
		$clean['custom_headers'] = array();

		$unreadable = array();

		foreach ( self::lines_to_list( $settings['custom_headers'] ?? array() ) as $line ) {
			$pair = self::header_pair( $line );

			if ( null === $pair ) {
				$unreadable[] = $line;

				continue;
			}

			$clean['custom_headers'][] = $pair[0] . ': ' . $pair[1];
		}

		// Only a custom CDN reads these, so only a custom CDN is refused over them.
		if ( 'custom' !== $clean['provider'] ) {
			return $clean;
		}

		if ( array() !== $unreadable ) {
			$errors['custom_headers'] = sprintf(
				/* translators: 1: the rejected lines, 2: the signal names. */
				__( 'These are not a signal the firewall can read and a header name: %1$s. Write one "signal: Header-Name" per line, where the signal is one of %2$s.', 'basic-firewall' ),
				implode( '; ', $unreadable ),
				implode( ', ', self::FIELDS )
			);

			return $clean;
		}

		if ( array() === $clean['custom_headers'] ) {
			$errors['custom_headers'] = __( 'Name at least one header, as "signal: Header-Name". A custom CDN naming no headers is a configuration the firewall refuses to start on, which would stop every rule being enforced rather than just this one.', 'basic-firewall' );
		}

		return $clean;
	}

	/**
	 * Read one "signal: Header-Name" line.
	 *
	 * @param string $line The line.
	 *
	 * @return array{0: string, 1: string}|null The signal and header, or null when either is unusable.
	 */
	public static function header_pair( string $line ): ?array {
		$parts = explode( ':', $line, 2 );

		if ( 2 !== count( $parts ) ) {
			return null;
		}

		$field  = strtolower( trim( $parts[0] ) );
		$header = trim( $parts[1] );

		if ( ! in_array( $field, self::FIELDS, true ) || '' === $header || ! Response_Settings::is_header_name( $header ) ) {
			return null;
		}

		return array( $field, $header );
	}

	/**
	 * The header map a custom CDN compiles to.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return array<string, string> Signal to header name.
	 */
	public static function header_map( array $settings ): array {
		$map = array();

		foreach ( self::lines_to_list( $settings['custom_headers'] ?? array() ) as $line ) {
			$pair = self::header_pair( $line );

			if ( null !== $pair ) {
				$map[ $pair[0] ] = $pair[1];
			}
		}

		return $map;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry    = parent::compile( $rule );
		$settings = (array) ( $rule['settings'] ?? array() );

		/*
		 * A provider the library does not know is a configuration error at
		 * startup, which takes every rule down with it. Only the rule screen
		 * validates, so an imported value is brought back to the default here
		 * rather than handed on.
		 */
		$provider = (string) ( $settings['provider'] ?? 'cloudflare' );
		$provider = in_array( $provider, self::PROVIDERS, true ) ? $provider : 'cloudflare';

		$metadata             = $entry['metadata'] ?? array();
		$metadata['provider'] = $provider;

		/*
		 * Only for a custom CDN. The named ones carry their header map in the
		 * library, and writing a second copy beside it would go stale the next
		 * time a CDN renames something.
		 */
		if ( 'custom' === $provider ) {
			$metadata['headers'] = self::header_map( $settings );
		}

		$entry['metadata'] = $metadata;

		return $entry;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function summarize( array $settings ): array {
		$names = array(
			'cloudflare' => __( 'Cloudflare', 'basic-firewall' ),
			'fastly'     => __( 'Fastly', 'basic-firewall' ),
			'custom'     => __( 'a custom CDN', 'basic-firewall' ),
		);

		$lines   = parent::summarize( $settings );
		$lines[] = sprintf(
			/* translators: %s: the CDN. */
			__( 'Read from %s.', 'basic-firewall' ),
			$names[ (string) ( $settings['provider'] ?? 'cloudflare' ) ] ?? $names['cloudflare']
		);

		return $lines;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function check_requirements( array $settings ): array {
		$problems = parent::check_requirements( $settings );

		/*
		 * The one failure nobody notices, as for a geolocation rule reading the
		 * CDN: without trusted proxies the library ignores every edge header,
		 * and a bot rule that never matches is indistinguishable from no bots
		 * visiting.
		 */
		if ( 'yes' !== (string) Plugin::instance()->settings()->get( 'global.behind_proxy', 'unknown' ) ) {
			$problems[] = __( 'This rule reads headers your CDN sets, but the site has not been told it is behind a proxy. The firewall will not believe the headers, so the rule matches nothing. Answer the proxy question on the General screen and configure your trusted proxies.', 'basic-firewall' );
		}

		if ( 'custom' === ( $settings['provider'] ?? 'cloudflare' ) && array() === self::header_map( $settings ) ) {
			$problems[] = __( 'This rule reads from a custom CDN but names no headers it can read. It is skipped when the configuration is compiled, because the firewall refuses to start on it.', 'basic-firewall' );
		}

		return $problems;
	}
}
