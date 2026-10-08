<?php
/**
 * The user agent rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Support\Reverse_Dns;
use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\Firewall\Plugins\UserAgent;

/**
 * Matches on a parsed user agent rather than on the header as a string.
 *
 * The one thing to know before writing a rule here is the difference between
 * `bot` and `automated`, because it decides whether the rule stops scanners:
 *
 * | Agent                  | `bot:true`  | `automated:true` |
 * |------------------------|-------------|------------------|
 * | `sqlmap/1.7`           | allowed     | **blocked**      |
 * | Nikto's default agent  | **blocked** | **blocked**      |
 * | `curl/8.0`             | allowed     | **blocked**      |
 * | `python-requests/2.31` | allowed     | **blocked**      |
 * | `Googlebot/2.1`        | blocked     | blocked          |
 * | iPhone Safari          | allowed     | allowed          |
 *
 * `bot` is backed by a curated database of known crawlers, which does not
 * classify most scanners or generic HTTP client libraries. **A rule written as
 * `bot equals true` lets sqlmap, curl and python-requests straight through.**
 * Nikto's default agent is the exception: device-detector 6.5.2, the minimum
 * kanopi/firewall 2.34.0 requires, added it to the database.
 * `automated` is that database plus a broader crawler list, and is almost always
 * the condition somebody means.
 *
 * The rule screen says this at the point the variable is chosen, because the
 * names do not suggest it and the failure is invisible.
 *
 * The other thing to know is that the agent is **whatever the client typed**.
 * That is harmless on a block rule -- the cost of being lied to is an attacker
 * declining to be blocked -- and it turns an allow rule for `bot equals true`
 * into a skeleton key, since `response: allow` ends evaluation and anyone can
 * send `Googlebot/2.1`. Reverse-DNS verification is the fix: see
 * validate_settings() for what is refused and why.
 */
final class User_Agent extends Condition_Rule_Type_Base {

	/**
	 * What the screen stores for "what `bot` consults", and the library's name.
	 *
	 * The screen's words are kept in storage because they are what a person
	 * chose between; the library's are what compiles. Every value on the right
	 * is one of UserAgent::BOT_DETECTORS, which a test holds it to.
	 *
	 * @var array<string, string>
	 */
	public const BOT_DETECTORS = array(
		'curated' => 'device-detector',
		'wider'   => 'crawler-detect',
		'either'  => 'both',
	);

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'user_agent';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'User agent', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Matches a parsed user agent: whether it is automated, which browser, device, operating system or brand. Parsed, not string-matched.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return UserAgent::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -90;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return parent::default_settings() + array(

			/*
			 * Identifying an agent means compiling a 1.7 MB pattern set -- about
			 * 618 ms the first time each PHP process does it, and every php-fpm
			 * worker pays it again after a recycle. Cached into the private
			 * directory rather than the system temporary directory, because a
			 * temp directory gets cleared and every clear costs that 618 ms
			 * again on every worker.
			 */
			'cache_detection'   => true,

			/*
			 * Which list `bot` consults. Widening it changes what an existing
			 * bot rule blocks, so it is a stored choice rather than a default
			 * that moved underneath somebody.
			 */
			'bot_source'        => 'curated',

			/*
			 * Off, and only meaningful with a domain list. The library treats
			 * verification with no domains as "match nobody", which is correct
			 * of it and not a state worth being able to save.
			 */
			'verify'            => false,
			'verify_suffixes'   => array(),

			/*
			 * The site's choice, from the General screen, unless a rule makes
			 * its own (library 2.38.0). Empty and 0 both mean "the site's".
			 */
			'verify_provider'   => '',
			'verify_timeout_ms' => 0,
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * The condition editor renders conditions only, so everything else this
	 * type stores is rendered from here -- see Rule_Edit_Screen::render_settings().
	 */
	public function settings_help(): array {
		$help = array(
			'cache_detection' => array(
				'label'       => __( 'Cache agent detection', 'basic-firewall' ),
				'description' => __( 'Keeps the compiled detection patterns wherever the firewall caches — files, the object cache or APCu, chosen on the Storage screen for every rule at once. Identifying an agent means compiling a 1.7 MB pattern set — about 618 ms each time it is not cached — so turn this off only to rule the cache out while debugging.', 'basic-firewall' ),
			),
			'bot_source'      => array(
				'label'       => __( 'What bot consults', 'basic-firewall' ),
				'description' => __( 'Widening this changes what an existing <code>bot</code> rule matches. It does not make <code>bot</code> catch scanners — use <code>automated</code> for that.', 'basic-firewall' ),
				'choices'     => array(
					'curated' => __( 'The curated crawler database (the library default)', 'basic-firewall' ),
					'wider'   => __( 'The wider crawler list', 'basic-firewall' ),
					'either'  => __( 'Either', 'basic-firewall' ),
				),
			),
		);

		$capabilities = new Library_Capabilities();

		// Not offered where the library would ignore it; see has_identity_verification().
		if ( ! $capabilities->has_identity_verification() ) {
			return $help;
		}

		$verify = __( 'A user agent is whatever the client typed. An allow rule for <code>bot equals true</code> is therefore a skeleton key: anyone can send <code>Googlebot/2.1</code> and be let past every rule below it. Verification does the round trip Google, Bing, Apple and DuckDuckGo all document — reverse-resolve the address, check the hostname is in a domain you list, then forward-resolve that hostname and confirm it comes back to the same address. Reverse DNS alone proves nothing; the forward confirmation is what makes it proof.<br><br><strong>Fails closed:</strong> no PTR record, a hostname outside your list, a forward lookup that does not return, or DNS being unreachable all mean the rule does not match. On an allow rule that is the safe direction — an unverified client is treated as ordinary traffic.<br><br><strong>A local caching resolver is a prerequisite.</strong> Measured upstream at about 112 ms cold — 38 ms reverse plus 74 ms forward — against 3.5–5 ms for the firewall\'s entire evaluation. <code>systemd-resolved</code>, <code>dnsmasq</code> or <code>unbound</code> takes that to roughly 2 ms. A verdict is cached, and verification only runs once the rule\'s conditions have matched, but a cache miss pays the cold figure — and PHP cannot put a timeout on its own DNS lookups. Where there is no local resolver, choose a DNS-over-HTTPS provider under <strong>Crawler verification</strong> on the General screen: each lookup is then cut off at a time limit.', 'basic-firewall' );

		if ( ! $capabilities->identity_verification_runs() ) {
			$verify = __( '<strong>This cannot run on this site yet.</strong> The installed firewall library switches verification off whenever rule lists are kept off the request path, which they are unless <code>BASIC_FIREWALL_SOURCES_OFFLINE</code> is defined as <code>false</code> — so a rule that verifies would match nobody. kanopi/firewall 2.33.0 gives verification its own switch; until then, defining that constant also lets imported rule lists refresh while a visitor waits.', 'basic-firewall' ) . '<br><br>' . $verify;
		}

		return $help + array(
			'verify'            => array(
				'label'       => __( 'Verify the crawler', 'basic-firewall' ),
				'checkbox'    => __( 'Only match when the client verifies by reverse DNS', 'basic-firewall' ),
				'description' => $verify,
			),
			'verify_suffixes'   => array(
				'label'       => __( 'Accepted domains', 'basic-firewall' ),
				'description' => __( 'One per line — <code>googlebot.com</code>, <code>search.msn.com</code>, <code>applebot.apple.com</code>, <code>duckduckgo.com</code>. Matched on a label boundary, so <code>googlebot.com</code> does not accept <code>evilgooglebot.com</code>. Required when verifying.', 'basic-firewall' ),
				'show_when'   => 'settings[verify]:1',
			),
			'verify_provider'   => array(
				'label'       => __( 'Who makes the lookups', 'basic-firewall' ),
				'choices'     => Reverse_Dns::choices( __( 'The site\'s choice, on the General screen', 'basic-firewall' ) ),
				'description' => __( 'Usually left to the site. A provider chosen here is used for this rule only, and receives the reverse-DNS name of each address this rule asks about — the visitor\'s IP address, written backwards. A rule cannot choose PHP\'s own lookups while the site uses a provider.', 'basic-firewall' ),
				'show_when'   => 'settings[verify]:1',
			),
			'verify_timeout_ms' => array(
				'label'       => __( 'Time limit per lookup, in milliseconds', 'basic-firewall' ),
				'description' => sprintf(
					/* translators: %d: the largest time limit. */
					__( '0 uses the site\'s. Applies only when a provider makes the lookups; PHP\'s own lookups cannot be given one. At most %d.', 'basic-firewall' ),
					Reverse_Dns::max_timeout_ms()
				),
				'show_when'   => 'settings[verify]:1',
			),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	protected function variable_options(): array {
		/*
		 * Exactly the vocabulary UserAgent::getValue() understands, and no more.
		 *
		 * This list is what the validator checks a condition against, so an
		 * entry here that the library does not resolve produces a rule that
		 * saves, reports itself as active, and matches nothing -- the failure
		 * this plugin exists to prevent. There is deliberately no `user_agent`
		 * variable: the plugin matches a *parsed* agent, and the raw header is
		 * reached through a Request / URL rule on `header.user-agent` instead.
		 */
		return array(
			'automated'      => __( 'Automated — the curated bot database plus the wider crawler list. This is the one that stops scanners.', 'basic-firewall' ),
			'bot'            => __( 'Bot — the curated crawler database only. Does not classify sqlmap, curl or python-requests.', 'basic-firewall' ),
			'bot.name'       => __( 'Bot name', 'basic-firewall' ),
			'bot.category'   => __( 'Bot category — only populated by the curated database', 'basic-firewall' ),
			'bot.producer'   => __( 'Bot producer — only populated by the curated database', 'basic-firewall' ),
			'bot.url'        => __( 'Bot URL — only populated by the curated database', 'basic-firewall' ),
			'client.name'    => __( 'Client name, such as Chrome or curl', 'basic-firewall' ),
			'client.type'    => __( 'Client type, such as browser or library', 'basic-firewall' ),
			'client.version' => __( 'Client version', 'basic-firewall' ),
			'os.name'        => __( 'Operating system name', 'basic-firewall' ),
			'os.short_name'  => __( 'Operating system short name', 'basic-firewall' ),
			'os.version'     => __( 'Operating system version', 'basic-firewall' ),
			'device.type'    => __( 'Device type, such as desktop or smartphone', 'basic-firewall' ),
			'brand'          => __( 'Device brand', 'basic-firewall' ),
			'model'          => __( 'Device model', 'basic-firewall' ),
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

		$source = (string) ( $settings['bot_source'] ?? 'curated' );

		$clean['bot_source']      = isset( self::BOT_DETECTORS[ $source ] ) ? $source : 'curated';
		$clean['cache_detection'] = ! empty( $settings['cache_detection'] );

		$suffixes = self::normalise_suffixes( $settings['verify_suffixes'] ?? array() );

		/*
		 * What is not a domain is dropped from what is kept, and named. A URL,
		 * a wildcard or an address would never match anything, so storing one
		 * is an allow rule that silently never fires rather than a typo.
		 */
		$implausible = array_values( array_filter( $suffixes, static fn ( string $suffix ): bool => ! self::is_plausible_suffix( $suffix ) ) );

		$clean['verify']          = ! empty( $settings['verify'] );
		$clean['verify_suffixes'] = array_values( array_diff( $suffixes, $implausible ) );

		/*
		 * Kept when verification is off, as the domains are, so ticking it
		 * again brings the rule's choice back. A provider the library would
		 * refuse -- unknown, or no curl on this PHP -- is not stored: it would
		 * stop the firewall starting, and the compiler would drop it anyway.
		 */
		$provider = trim( (string) ( $settings['verify_provider'] ?? '' ) );
		$problem  = '' === $provider ? null : Reverse_Dns::provider_problem( $provider );
		$timeout  = $settings['verify_timeout_ms'] ?? 0;
		$timeout  = '' === $timeout ? 0 : ( is_numeric( $timeout ) ? (int) $timeout : -1 );

		$clean['verify_provider']   = null === $problem ? $provider : '';
		$clean['verify_timeout_ms'] = $timeout >= 0 && $timeout <= Reverse_Dns::max_timeout_ms() ? $timeout : 0;

		if ( ! $clean['verify'] ) {
			return $clean;
		}

		/*
		 * Refused rather than warned about, all three. Each is a rule the screen
		 * would describe as verifying crawlers while it verifies nobody -- the
		 * operator believes genuine crawlers are let through, and every one of
		 * them is instead judged by whatever rules follow.
		 *
		 * The verify flag itself is kept either way. Only the rule screen shows
		 * these errors; everywhere else that writes settings discards them, and
		 * turning verification off behind somebody's back is the one repair
		 * that would change what the rule does.
		 */
		$capabilities = new Library_Capabilities();

		if ( ! $capabilities->identity_verification_runs() ) {
			$errors['verify'] = $capabilities->has_identity_verification()
				? __( 'Verification cannot run while the firewall keeps rule lists off the request path, so a rule that verifies would match nobody. Define BASIC_FIREWALL_SOURCES_OFFLINE as false in wp-config.php first, update to kanopi/firewall 2.33.0, or leave verification off.', 'basic-firewall' )
				: __( 'The installed firewall library cannot verify a crawler, and would ignore the setting — letting through everybody who claims to be one. Leave verification off.', 'basic-firewall' );

			return $clean;
		}

		if ( array() !== $implausible ) {
			$errors['verify_suffixes'] = sprintf(
				/* translators: %s: the rejected entries. */
				__( '%s is not a domain. Write the crawler domain on its own, such as googlebot.com — no scheme, path, port or wildcard, and at least two labels.', 'basic-firewall' ),
				implode( ', ', $implausible )
			);

			return $clean;
		}

		if ( array() === $clean['verify_suffixes'] ) {
			$errors['verify_suffixes'] = __( 'List at least one domain to accept. Without one, any host with a PTR record would pass — which is not verification, and the firewall treats it as matching nobody.', 'basic-firewall' );
		}

		if ( null !== $problem ) {
			$errors['verify_provider'] = $problem;
		}

		if ( $clean['verify_timeout_ms'] !== $timeout ) {
			$errors['verify_timeout_ms'] = sprintf(
				/* translators: %d: the largest time limit. */
				__( 'A whole number of milliseconds from 0, for the site\'s, to %d.', 'basic-firewall' ),
				Reverse_Dns::max_timeout_ms()
			);
		}

		return $clean;
	}

	/**
	 * Whether a rule asks to verify crawlers and has no domain to verify against.
	 *
	 * The rule screen refuses to save this, but an import, WP-CLI, a seed
	 * script or `wp option update` can store it: the validator drops every
	 * entry that is not a domain -- `*.googlebot.com`, a URL -- and keeps the
	 * verify flag, so `verify: true` with an empty list is what is left. A rule
	 * in that state has to be skipped when the configuration is compiled, not
	 * compiled without its verification, because on an allow rule the second
	 * lets through everybody who claims to be a crawler.
	 *
	 * @param array<string, mixed> $settings The rule's stored settings.
	 */
	public static function verification_unusable( array $settings ): bool {
		return ! empty( $settings['verify'] ) && array() === self::usable_suffixes( $settings );
	}

	/**
	 * The accepted domains a verifying rule can actually compile.
	 *
	 * @param array<string, mixed> $settings The rule's stored settings.
	 *
	 * @return list<string>
	 */
	private static function usable_suffixes( array $settings ): array {
		return array_values( array_filter( self::normalise_suffixes( $settings['verify_suffixes'] ?? array() ), array( self::class, 'is_plausible_suffix' ) ) );
	}

	/**
	 * Split the accepted domains into a clean list.
	 *
	 * Stored without the leading dot the library documents, because matching
	 * is on a label boundary either way and what the screen shows back should
	 * be what was typed. Lower-cased, a trailing root dot dropped, duplicates
	 * collapsed.
	 *
	 * @param mixed $value A textarea's content, or an already-split list.
	 *
	 * @return list<string>
	 */
	public static function normalise_suffixes( $value ): array {
		$suffixes = array();

		foreach ( self::lines_to_list( $value ) as $line ) {
			$line = trim( strtolower( $line ), '.' );

			if ( '' !== $line && ! in_array( $line, $suffixes, true ) ) {
				$suffixes[] = $line;
			}
		}

		return $suffixes;
	}

	/**
	 * Whether a string could be a domain a crawler reverse-resolves into.
	 *
	 * Deliberately strict, and at least two labels: a bare `com` would accept
	 * every host under it, which is a hostname check that checks nothing.
	 *
	 * @param string $suffix The candidate, already normalised.
	 */
	public static function is_plausible_suffix( string $suffix ): bool {
		return 1 === preg_match( '/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/', $suffix );
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function summarize( array $settings ): array {
		$lines = parent::summarize( $settings );

		if ( ! empty( $settings['verify'] ) ) {
			$suffixes = self::usable_suffixes( $settings );

			$lines[] = array() === $suffixes
				? __( 'Verified by reverse DNS — but no domain is listed, so the rule is skipped and matches nobody.', 'basic-firewall' )
				: sprintf(
					/* translators: %s: comma-separated domains. */
					__( 'Only when verified by reverse DNS into %s.', 'basic-firewall' ),
					implode( ', ', $suffixes )
				);

			$provider = (string) ( $settings['verify_provider'] ?? '' );

			if ( '' !== $provider ) {
				$lines[] = sprintf(
					/* translators: %s: a DNS-over-HTTPS provider's name. */
					__( 'Lookups made by %s.', 'basic-firewall' ),
					$provider
				);
			}
		}

		return $lines;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function check_requirements( array $settings ): array {
		$problems = parent::check_requirements( $settings );

		if ( empty( $settings['verify'] ) ) {
			return $problems;
		}

		$capabilities = new Library_Capabilities();

		if ( ! $capabilities->has_identity_verification() ) {
			$problems[] = __( 'This rule asks to verify crawlers, which the installed firewall library cannot do. It is skipped when the configuration is compiled, rather than compiled into a rule that believes every client claiming to be a crawler.', 'basic-firewall' );
		} elseif ( ! $capabilities->identity_verification_runs() ) {
			$problems[] = __( 'This rule verifies crawlers, but verification cannot run while rule lists are kept off the request path — so it matches nobody. Define BASIC_FIREWALL_SOURCES_OFFLINE as false, or update to kanopi/firewall 2.33.0.', 'basic-firewall' );
		} elseif ( self::verification_unusable( $settings ) ) {
			$problems[] = __( 'This rule verifies crawlers but lists no domain to accept — an entry that is not a plain domain, such as *.googlebot.com or a URL, is dropped. It is skipped when the configuration is compiled, rather than compiled into a rule that believes every client claiming to be a crawler, so it matches nobody. List a domain such as googlebot.com.', 'basic-firewall' );
		}

		return $problems;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry    = parent::compile( $rule );
		$settings = $rule['settings'] ?? array();

		$metadata = $entry['metadata'] ?? array();

		/*
		 * Off, or nothing. Where the corpus is cached is one site-wide choice
		 * made on the Storage screen and applied by the compiler, which is the
		 * only place that knows this rule's final index.
		 *
		 * This used to write `metadata.cache_dir`, a key the library has never
		 * read -- it reads `metadata.cache.dir` -- so the corpus was always in
		 * KANOPI_FIREWALL_CACHE_DIR whatever the file said. Emitting nothing
		 * says what was actually happening.
		 */
		if ( empty( $settings['cache_detection'] ) ) {
			$metadata['cache'] = false;
		}

		/*
		 * `bot_detector`, in the library's vocabulary. This wrote the stored
		 * `bot_source` as it was, a key the library has never read, so every
		 * choice behaved as the default: "the wider list" still let sqlmap
		 * through `bot equals true`.
		 *
		 * Nothing for the curated database, which is the library's default.
		 * Naming it explicitly is how an operator tells the library they have
		 * thought about the coverage gap, and it then stops logging the notice
		 * that `bot` misses scanners -- a default nobody chose is not that.
		 */
		$detector = self::BOT_DETECTORS[ (string) ( $settings['bot_source'] ?? 'curated' ) ] ?? null;

		if ( null !== $detector && UserAgent::BOT_DETECTOR_DEFAULT !== $detector ) {
			$metadata['bot_detector'] = $detector;
		}

		/*
		 * Verification with no usable domain compiles as verification all the
		 * same: an empty list, which the library reads as "match nobody".
		 * Dropping the keys instead would leave a plain agent match, and on an
		 * allow rule that is a skeleton key for anyone sending Googlebot/2.1.
		 * The compiler skips such a rule before it gets here -- see
		 * verification_unusable() -- so this is the second line, for anything
		 * that calls compile() without asking first.
		 *
		 * `verify_offline: false` rides along on every verifying rule, where
		 * the library honours it. Without it the verifier follows
		 * KANOPI_FIREWALL_SOURCES_OFFLINE, which both evaluation paths turn on
		 * so that a rule-list refresh never lands on a visitor's request -- and
		 * which, before kanopi/firewall 2.33.0 split the two, made every
		 * verifying rule match nobody. Written unconditionally rather than only
		 * when the constant is on, so the compiled file means the same thing on
		 * both paths and on every host.
		 */
		if ( ! empty( $settings['verify'] ) ) {
			$metadata['verify']          = 'reverse-dns';
			$metadata['verify_suffixes'] = self::usable_suffixes( $settings );

			if ( ( new Library_Capabilities() )->has_verification_switch() ) {
				$metadata['verify_offline'] = false;
			}

			/*
			 * Only when the rule makes its own choice; otherwise the library
			 * takes `global.reverse_dns`, which is the site's. The compiler
			 * checks the finished file and drops a choice the library would
			 * refuse to start on -- see Reverse_Dns::repair().
			 */
			$provider = trim( (string) ( $settings['verify_provider'] ?? '' ) );
			$timeout  = (int) ( $settings['verify_timeout_ms'] ?? 0 );

			if ( '' !== $provider ) {
				$metadata['verify_provider'] = $provider;
			}

			if ( $timeout > 0 ) {
				$metadata['verify_timeout_ms'] = $timeout;
			}
		}

		$entry['metadata'] = $metadata;

		return $entry;
	}
}
