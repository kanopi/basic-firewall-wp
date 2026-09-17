<?php
/**
 * The rate limit rule type.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType\Types;

use Kanopi\BasicFirewall\Compiler\Library_Map;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\RuleType\Rule_Type_Base;
use Kanopi\Firewall\Plugins\RateLimit;

/**
 * Limits how many requests one address may make against a pattern.
 *
 * **Read this before designing anything around it.** The counter is keyed on
 * the visitor's address and *the pattern that matched* -- `rate:{ip}:{pattern}`
 * -- not on the path they asked for. That single detail decides how every limit
 * behaves and it is the opposite of what "requests per path" suggests:
 *
 * | You configure                         | What it actually limits                                          |
 * |---------------------------------------|------------------------------------------------------------------|
 * | `/api/*` at 100/min                   | 100 per address across **everything below `/api/` combined**      |
 * | `/user/login` at 5/min                | 5 per address for that exact path                                 |
 * | the fallback, applied to other paths  | **one** count per address across all uncovered paths together     |
 *
 * Two consequences catch people out.
 *
 * **Visitors sharing an address share a count.** One office behind one NAT is
 * one bucket. So is a corporate VPN, a school, or a mobile carrier's gateway.
 * And if the site is behind a CDN with trusted proxies unconfigured, *every*
 * visitor shares one address and one bucket.
 *
 * **A limit cannot depend on who is asking.** The account is not part of the
 * key, so a different allowance for logged-in, anonymous or premium users cannot
 * be expressed here. A premium *endpoint* can carry its own limit; a premium
 * *user* cannot. Per-user quotas belong in the application, where the account is
 * known.
 */
final class Rate_Limit extends Rule_Type_Base {

	/**
	 * {@inheritDoc}
	 */
	public function id(): string {
		return 'rate_limit';
	}

	/**
	 * {@inheritDoc}
	 */
	public function label(): string {
		return __( 'Rate limit', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function description(): string {
		return __( 'Limits how many requests one address may make against each pattern you list, within a time window. Needs its own counter storage.', 'basic-firewall' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function library_class(): string {
		return RateLimit::class;
	}

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return -20;
	}

	/**
	 * A rate limit decides for itself what it returns.
	 *
	 * {@inheritDoc}
	 */
	public function supports_shared_status_code(): bool {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return array(
			'paths'                => array(),
			'default_limit'        => 60,
			'default_window'       => 60,

			/*
			 * On, matching the library, but offered as a tick box because it is
			 * the difference between limiting what you listed and capping the
			 * whole site. Untick it to limit only the listed patterns.
			 */
			'limit_unlisted_paths' => true,
			'status_code'          => 429,
			'storage'              => array(
				'backend'           => 'file',
				'file'              => 'ratelimit.data',
				'connection_source' => 'wordpress',
				'dsn'               => '',
				'table'             => 'basic_firewall_ratelimit',
				'redis_host'        => '127.0.0.1',
				'redis_port'        => 6379,
				'redis_password'    => '',
				'key_prefix'        => '',
			),
		);
	}

	/**
	 * {@inheritDoc}
	 */
	public function settings_help(): array {
		return array(
			'paths' => array(
				'label'       => __( 'Limits', 'basic-firewall' ),
				'description' => wp_kses_post(
					__( 'One per line, as <code>pattern requests seconds</code> — <code>/wp-login.php 5 300</code> is five attempts in five minutes.<br><br>A fourth field names <strong>what to count</strong>, comma separated. Left off, the firewall counts the client address and the pattern, which is what it has always done. <code>/login 5 300 post.log</code> counts the account being tried rather than the address trying it, so a credential-stuffing run spread over a thousand addresses still hits one limit. <code>/api/* 100 60 client_ip,path</code> counts each endpoint separately rather than the API as a whole.', 'basic-firewall' )
				),
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
		$paths = array();

		foreach ( self::path_lines( $settings['paths'] ?? array() ) as $line ) {
			/*
			 * An entry arrives either as the "pattern limit window" line the
			 * textarea produces, or as the map this method produced last time.
			 *
			 * Both, because this method is no longer only called on what a
			 * human typed: the importer runs it over an incoming document, and
			 * a document exported from this plugin already holds the map. Read
			 * as a line, the map stringified to "Array" and was rejected --
			 * so importing a rate limit rule exported from this very plugin
			 * silently produced a rule with no limits in it.
			 */
			$key = array();

			if ( is_array( $line ) ) {
				$pattern = (string) ( $line['pattern'] ?? '' );
				$limit   = (int) ( $line['limit'] ?? 0 );
				$window  = (int) ( $line['window'] ?? 0 );
				$key     = self::parse_key( implode( ',', (array) ( $line['key'] ?? array() ) ) );
				$line    = trim( $pattern . ' ' . $limit . ' ' . $window );
			} else {
				// "pattern limit window", whitespace or pipe separated.
				$split = preg_split( '/\s*[|]\s*|\s+/', $line );
				$parts = is_array( $split ) ? $split : array();

				$pattern = (string) ( $parts[0] ?? '' );
				$limit   = (int) ( $parts[1] ?? 0 );
				$window  = (int) ( $parts[2] ?? 0 );
				$key     = self::parse_key( implode( ',', array_slice( $parts, 3 ) ) );
			}

			if ( '' === $pattern || $limit < 1 || $window < 1 ) {
				$errors['paths'] = sprintf(
					/* translators: %s: the rejected line. */
					__( '%s is not a limit. Write one per line, as "pattern requests seconds" — for example "/wp-login.php 5 300". A fourth field names what to count, comma separated: "/login 5 300 post.log" counts the account rather than the address.', 'basic-firewall' ),
					$line
				);

				continue;
			}

			/*
			 * A path that both opens and closes with a slash satisfies the
			 * library's "is this a regex?" test and is treated as an unanchored
			 * regular expression -- so `/api/` matches any path containing
			 * "api", including `/rapidly`. This is the single most common way a
			 * rate limit ends up covering far more than intended.
			 */
			if ( strlen( $pattern ) > 1 && '/' === $pattern[0] && '/' === substr( $pattern, -1 ) ) {
				$errors['paths'] = sprintf(
					/* translators: 1: the pattern, 2: prefix form, 3: exact form. */
					__( '%1$s opens and closes with a slash, which the firewall reads as an unanchored regular expression — it would match any path containing that text. Use %2$s for a prefix, or %3$s for an exact match.', 'basic-firewall' ),
					$pattern,
					rtrim( $pattern, '/' ) . '/*',
					rtrim( $pattern, '/' )
				);

				continue;
			}

			$paths[] = array(
				'pattern' => $pattern,
				'limit'   => $limit,
				'window'  => $window,
				'key'     => $key,
			);
		}

		$storage = is_array( $settings['storage'] ?? null ) ? $settings['storage'] : array();
		$backend = (string) ( $storage['backend'] ?? 'file' );

		if ( ! isset( Library_Map::RATE_LIMIT_STORAGE[ $backend ] ) ) {
			$backend = 'file';
		}

		if ( 'memory' === $backend ) {
			$errors['storage.backend'] = __( 'In-memory counters are discarded when the request ends, so no visitor ever reaches a limit. The rule would evaluate and throw the result away while reporting itself as active.', 'basic-firewall' );
			$backend                   = 'file';
		}

		$status = (int) ( $settings['status_code'] ?? 429 );

		return array(
			'paths'                => $paths,
			'default_limit'        => max( 1, (int) ( $settings['default_limit'] ?? 60 ) ),
			'default_window'       => max( 1, (int) ( $settings['default_window'] ?? 60 ) ),
			'limit_unlisted_paths' => ! empty( $settings['limit_unlisted_paths'] ),
			'status_code'          => ( $status >= 100 && $status <= 599 ) ? $status : 429,
			'storage'              => array(
				'backend'           => $backend,
				'file'              => trim( (string) ( $storage['file'] ?? 'ratelimit.data' ) ),
				'connection_source' => (string) ( $storage['connection_source'] ?? 'wordpress' ),
				'dsn'               => trim( (string) ( $storage['dsn'] ?? '' ) ),
				'table'             => trim( (string) ( $storage['table'] ?? 'basic_firewall_ratelimit' ) ),
				'redis_host'        => trim( (string) ( $storage['redis_host'] ?? '127.0.0.1' ) ),
				'redis_port'        => (int) ( $storage['redis_port'] ?? 6379 ),
				'redis_password'    => (string) ( $storage['redis_password'] ?? '' ),
				'key_prefix'        => trim( (string) ( $storage['key_prefix'] ?? '' ) ),
			),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry    = $this->base_entry( $rule );
		$settings = $rule['settings'] ?? array();

		/*
		 * The library's shape, which is not the shape of the form.
		 *
		 * `config` is a LIST of rules, each `{path, rate, sample}` -- the plugin
		 * iterates it and reads `$rule['path']`, skipping anything that is not a
		 * string. The limits, the defaults and the storage all live where the
		 * library looks for them rather than where they were convenient to
		 * store.
		 *
		 * The first version of this wrote `config.limits` keyed by pattern with
		 * `limit`/`window` keys, plus `config.default_limit`. Every one of those
		 * names is ignored: the rule compiled cleanly, the screen showed it,
		 * `getFailedRules()` was empty, and four requests over the allowance all
		 * returned 404 because no limit was ever enforced. It was the end-to-end
		 * HTTP test that caught it -- nothing that calls the evaluator directly
		 * would have.
		 */
		$limits = array();

		foreach ( $settings['paths'] ?? array() as $path ) {
			/*
			 * The raw "pattern limit window" line is read here as well as the
			 * validated map, because only the rule form runs the validator --
			 * an imported document, a deploy writing the option or a hand edit
			 * all reach the compiler with whatever they stored. Skipping a raw
			 * line would have compiled a rate limit rule with fewer paths than
			 * it was configured with, and said nothing.
			 */
			if ( is_string( $path ) ) {
				$path = self::parse_path_line( $path );
			}

			if ( ! is_array( $path ) || '' === (string) ( $path['pattern'] ?? '' ) ) {
				continue;
			}

			$limit = array(
				'path'   => (string) $path['pattern'],
				'rate'   => (int) ( $path['limit'] ?? 0 ),
				// The library calls the window "sample".
				'sample' => (int) ( $path['window'] ?? 0 ),
			);

			/*
			 * Written only when named. Absent, the library counts the client
			 * address and the pattern -- byte-identical to what it counted
			 * before 2.27.0, so no counter resets on upgrade.
			 */
			$components = (array) ( $path['key'] ?? array() );

			if ( array() !== $components ) {
				$limit['key'] = array_values( array_map( 'strval', $components ) );
			}

			$limits[] = $limit;
		}

		$entry['config'] = $limits;

		$metadata = $entry['metadata'] ?? array();

		$metadata['default_rate']   = (int) ( $settings['default_limit'] ?? 60 );
		$metadata['default_sample'] = (int) ( $settings['default_window'] ?? 60 );

		/*
		 * Written explicitly rather than omitted. The library's own default is
		 * true, which applies the fallback allowance to every path the rule does
		 * not list -- capping the whole site from a rule that names one endpoint.
		 * A compiled file that says what is happening is worth more than one
		 * that depends on a default that can move.
		 */
		$metadata['limit_unlisted_paths'] = ! empty( $settings['limit_unlisted_paths'] );

		$metadata['storage'] = $this->compile_storage(
			is_array( $settings['storage'] ?? null ) ? $settings['storage'] : array()
		);

		$entry['metadata'] = $metadata;

		return $entry;
	}

	/**
	 * Compile the counter storage.
	 *
	 * @param array<string, mixed> $storage Stored counter settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_storage( array $storage ): array {
		$backend     = (string) ( $storage['backend'] ?? 'file' );
		$credentials = new Database_Credentials();

		$compiled = array(
			'type'   => Library_Map::resolve( Library_Map::RATE_LIMIT_STORAGE, $backend, 'file' ),
			'config' => array(),
		);

		if ( 'file' === $backend ) {
			// `file`, which is the key FileRateLimitStorage reads. Not
			// `storage_file`: that is the blocked-client store's key, and using
			// it here silently gets you the library's default path instead.
			$compiled['config']['file'] = Plugin::instance()->paths()->resolve(
				(string) ( $storage['file'] ?? 'ratelimit.data' )
			);

			return $compiled;
		}

		if ( 'database' === $backend ) {
			$source = (string) ( $storage['connection_source'] ?? 'wordpress' );
			$table  = (string) ( $storage['table'] ?? 'basic_firewall_ratelimit' );

			// Prefixed only when the table lives in WordPress's own database. A
			// supplied DSN points at a schema somebody named themselves, and
			// prefixing it would rename a table they created.
			$compiled['config']['storage-table'] = 'wordpress' === $source
				? $credentials->prefix_table( $table )
				: $table;

			if ( 'wordpress' === $source ) {
				/*
				 * Marked, not filled in. The runner replaces this with live
				 * credentials as a runtime override; the compiler records the
				 * intent because the plugin's index in the list -- which is what
				 * the override path needs -- only exists once every rule has been
				 * compiled.
				 */
				$compiled['config']['connection'] = array( '__wordpress' => true );
			} elseif ( '' !== trim( (string) ( $storage['dsn'] ?? '' ) ) ) {
				$compiled['config']['connection'] = array( 'dsn' => trim( (string) $storage['dsn'] ) );
			}

			return $compiled;
		}

		if ( 'redis' === $backend ) {
			// Nested under `redis`, which is where the library looks.
			$compiled['config']['redis'] = array(
				'host' => (string) ( $storage['redis_host'] ?? '127.0.0.1' ),
				'port' => (int) ( $storage['redis_port'] ?? 6379 ),
			);

			if ( '' !== (string) ( $storage['redis_password'] ?? '' ) ) {
				$compiled['config']['redis']['auth'] = (string) $storage['redis_password'];
			}

			/*
			 * The library defaults its Redis keys to a bare `ratelimit:`, so
			 * sibling sites sharing one Redis instance count each other's
			 * requests. A discriminator is inserted unless one was supplied.
			 */
			$prefix = trim( (string) ( $storage['key_prefix'] ?? '' ) );

			$compiled['config']['redis']['prefix'] = '' !== $prefix ? $prefix : $credentials->rate_limit_key_prefix();
		}

		return $compiled;
	}

	/**
	 * {@inheritDoc}
	 */
	public function secret_settings(): array {
		return array( 'storage.dsn', 'storage.redis_password' );
	}

	/**
	 * Split the stored paths, keeping maps intact.
	 *
	 * `lines_to_list()` casts every entry to a string, which is right for the
	 * textarea it was written for and wrong for a value this type stores
	 * structured. An already-validated path went through it as the string
	 * "Array".
	 *
	 * @param mixed $value Raw textarea content, a list of lines, or a list of maps.
	 *
	 * @return list<string|array<string, mixed>>
	 */
	private static function path_lines( $value ): array {
		if ( ! is_array( $value ) ) {
			return self::lines_to_list( $value );
		}

		$out = array();

		foreach ( $value as $entry ) {
			if ( is_array( $entry ) ) {
				$out[] = $entry;

				continue;
			}

			$entry = trim( (string) $entry );

			if ( '' !== $entry ) {
				$out[] = $entry;
			}
		}

		return $out;
	}

	/**
	 * Read one "pattern limit window" line.
	 *
	 * The stored-as-typed form, which is what the validator turns into a map
	 * and what everything that bypasses the validator leaves alone.
	 *
	 * @param string $line Raw line.
	 *
	 * @return array{pattern: string, limit: int, window: int}
	 */
	public static function parse_path_line( string $line ): array {
		$split = preg_split( '/\s*[|]\s*|\s+/', trim( $line ) );
		$parts = is_array( $split ) ? $split : array();

		return array(
			'pattern' => (string) ( $parts[0] ?? '' ),
			'limit'   => (int) ( $parts[1] ?? 0 ),
			'window'  => (int) ( $parts[2] ?? 0 ),

			/*
			 * A fourth field, comma-separated, naming what to count. Needs
			 * library 2.27.0; absent it counts the address and the pattern,
			 * which is what every earlier version did and what a line with
			 * three fields keeps doing.
			 *
			 * Everything from the fourth field on is rejoined before being
			 * split on commas, because the line is split on whitespace first:
			 * `client_ip, path` arrives as two fields, and taking only the
			 * first would drop half the key into a limit that counts something
			 * narrower than it was told to.
			 */
			'key'     => self::parse_key( implode( ',', array_slice( $parts, 3 ) ) ),
		);
	}

	/**
	 * Split the comma-separated key components of a path line.
	 *
	 * @param string $value Raw field.
	 *
	 * @return list<string>
	 */
	public static function parse_key( string $value ): array {
		return array_values(
			array_filter(
				array_map(
					static fn ( string $part ): string => strtolower( trim( $part ) ),
					explode( ',', $value )
				),
				static fn ( string $part ): bool => '' !== $part
			)
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function summarize( array $settings ): array {
		$paths = $settings['paths'] ?? array();

		if ( array() === $paths ) {
			$lines = array( __( 'No patterns listed.', 'basic-firewall' ) );
		} else {
			$lines = array();

			foreach ( array_slice( $paths, 0, 5 ) as $path ) {
				/*
				 * A path arrives parsed from the rule form and unparsed from
				 * everywhere else -- an imported document, a deploy writing the
				 * option, a hand edit -- because only the form runs
				 * validate_settings(). Reading the raw "pattern limit window"
				 * line here as well means a listing describes what is stored
				 * rather than throwing over it.
				 */
				if ( is_string( $path ) ) {
					$path = self::parse_path_line( $path );
				}

				if ( ! is_array( $path ) ) {
					continue;
				}

				$lines[] = sprintf(
					/* translators: 1: path pattern, 2: request count, 3: window in seconds. */
					__( '%1$s — %2$d request(s) per %3$d second(s)', 'basic-firewall' ),
					(string) ( $path['pattern'] ?? '' ),
					(int) ( $path['limit'] ?? 0 ),
					(int) ( $path['window'] ?? 0 )
				);
			}
		}

		if ( ! empty( $settings['limit_unlisted_paths'] ) ) {
			$lines[] = sprintf(
				/* translators: 1: request count, 2: window in seconds. */
				__( 'Every other path shares one allowance of %1$d per %2$d seconds.', 'basic-firewall' ),
				(int) ( $settings['default_limit'] ?? 60 ),
				(int) ( $settings['default_window'] ?? 60 )
			);
		}

		return $lines;
	}
}
