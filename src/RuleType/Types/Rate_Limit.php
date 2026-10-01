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
use Kanopi\BasicFirewall\Redis_Password;
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
 * That is the default, not the only choice. Since library 2.27.0 a limit line
 * can name what to count -- `post.log`, the username on the login form -- so the
 * budget belongs to an account rather than an address. It still cannot give
 * different accounts different allowances: a premium *endpoint* can carry its
 * own limit, a premium *user* cannot, and per-user quotas belong in the
 * application, where the account is known.
 */
final class Rate_Limit extends Rule_Type_Base {

	/**
	 * Key components that stand alone.
	 *
	 * `client_ip` and `rule_pattern` are the library's own default pair; the
	 * rest is the vocabulary the Request / URL rule already reads, because that
	 * is the vocabulary the library resolves them with.
	 */
	public const KEY_ATOMS = array( 'client_ip', 'rule_pattern', 'path', 'method', 'host', 'scheme', 'port', 'query' );

	/**
	 * Key components that take a name after a dot.
	 */
	public const KEY_PREFIXES = array( 'header', 'post', 'cookie', 'query' );

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
		return __( 'Limits how many requests one address may make against each pattern you list, within a time window, and answers the rest with 429 Too Many Requests. Needs its own counter storage.', 'basic-firewall' );
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

			/*
			 * No status code. There used to be one, defaulting to 429, and the
			 * library ignores it: RateLimit::getStatusCode() returns 429 and
			 * reads nothing. A field that changes nothing is a promise the
			 * firewall does not keep, so it went; a value an earlier build
			 * stored is dropped the next time the rule is validated.
			 */
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
		$storage = 'settings[storage][backend]';

		return array(
			'paths'   => array(
				'label'       => __( 'Limits', 'basic-firewall' ),

				/*
				 * Stored as maps, typed as lines. The screen writes each map
				 * back as the line it was read from; without this it printed
				 * "Array" for every limit, and saving the rule untouched was
				 * refused for having no limits in it.
				 */
				'lines'       => array( self::class, 'limit_lines' ),

				/*
				 * A pattern, read as typed: through the textarea sanitiser a
				 * `/caf%C3%A9/* 5 60` limit lost its percent-encodings and
				 * limited a different path (#60).
				 */
				'verbatim'    => true,
				'description' => wp_kses_post(
					__( 'One per line, as <code>pattern requests seconds</code> — <code>/wp-login.php 5 300</code> is five attempts in five minutes.<br><br>A fourth field names <strong>what to count</strong>, comma separated. Left off, the firewall counts the client address and the pattern, which is what it has always done. <code>/wp-login.php 5 300 post.log</code> counts the account being tried rather than the address trying it, so a credential-stuffing run spread over a thousand addresses still hits one limit. <code>/api/* 100 60 client_ip,path</code> counts each endpoint separately rather than the API as a whole. A header name is read in any case; a form field, cookie or query name exactly as written, so <code>post.userName</code> and <code>post.username</code> are different fields.<br><br><strong>A limit that counts an account is not a replacement for one that counts the address.</strong> The two catch opposite attacks — an account key misses one client walking a list of usernames, which gets a fresh budget per name — and a limit without <code>client_ip</code> in its key refuses but never bans. Keep an address-keyed limit on the same pattern, <em>in a separate rate limit rule</em>: within one rule only the first line whose pattern matches is ever used.', 'basic-firewall' )
				),
			),
			'storage' => array(
				'label'  => __( 'Counter storage', 'basic-firewall' ),

				/*
				 * Field by field, like the geolocation reader. The storage map
				 * used to be a textarea of `key: value` lines -- the Redis
				 * password in clear among them -- which posted back as a string
				 * the validator did not recognise, so every save reset the
				 * storage to a file and dropped the password.
				 */
				'fields' => array(
					'backend'           => array(
						'label'       => __( 'Keep the counters in', 'basic-firewall' ),
						'choices'     => array(
							'file'     => __( 'A file in the private directory', 'basic-firewall' ),
							'database' => __( 'A database table', 'basic-firewall' ),
							'redis'    => __( 'Redis', 'basic-firewall' ),
						),
						'description' => __( 'A file is enough for one web server. Several servers behind a load balancer each keep their own file, so each allows the full limit — use the database or Redis there.', 'basic-firewall' ),
					),
					'file'              => array(
						'label'       => __( 'Counter file', 'basic-firewall' ),
						'description' => __( 'A relative path resolves inside the private directory.', 'basic-firewall' ),
						'show_when'   => $storage . ':file',
					),
					'connection_source' => array(
						'label'     => __( 'Connection', 'basic-firewall' ),
						'choices'   => array(
							'wordpress' => __( 'WordPress\'s own database', 'basic-firewall' ),
							'dsn'       => __( 'A DSN', 'basic-firewall' ),
						),
						'show_when' => $storage . ':database',
					),
					'dsn'               => array(
						'label'       => __( 'DSN', 'basic-firewall' ),
						'secret'      => true,
						'description' => __( 'A DSN carries its password, so it is treated as one.', 'basic-firewall' ),
						'show_when'   => 'settings[storage][connection_source]:dsn',
					),
					'table'             => array(
						'label'       => __( 'Table', 'basic-firewall' ),
						'description' => __( 'In WordPress\'s database the table prefix is added for you.', 'basic-firewall' ),
						'show_when'   => $storage . ':database',
					),
					'redis_host'        => array(
						'label'     => __( 'Redis host', 'basic-firewall' ),
						'show_when' => $storage . ':redis',
					),
					'redis_port'        => array(
						'label'     => __( 'Redis port', 'basic-firewall' ),
						'show_when' => $storage . ':redis',
					),
					'redis_password'    => array(
						'label'       => __( 'Redis password', 'basic-firewall' ),
						'secret'      => true,
						'description' => Redis_Password::is_overridden()
							? sprintf(
								/* translators: %s: constant name. */
								__( 'Overridden: the <code>%s</code> constant in wp-config.php supplies the password for every Redis connection, and anything stored here is not used while it is defined. It is injected on each request and never written to the compiled file.', 'basic-firewall' ),
								esc_html( Redis_Password::CONSTANT )
							)
							: sprintf(
								/* translators: %s: constant name. */
								__( 'Typed here, the password is written into the compiled file in plain text, because requests answered before WordPress loads can read nothing else. Defining <code>%s</code> in wp-config.php keeps it out of every file, for this and the block list.', 'basic-firewall' ),
								esc_html( Redis_Password::CONSTANT )
							),
						'show_when'   => $storage . ':redis',
					),
					'key_prefix'        => array(
						'label'       => __( 'Key prefix', 'basic-firewall' ),
						'description' => __( 'Left empty, one is derived from the site, so sites sharing one Redis do not count each other\'s requests.', 'basic-firewall' ),
						'show_when'   => $storage . ':redis',
					),
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
			if ( is_array( $line ) ) {
				$pattern = (string) ( $line['pattern'] ?? '' );
				$limit   = (int) ( $line['limit'] ?? 0 );
				$window  = (int) ( $line['window'] ?? 0 );
				$raw_key = implode( ',', array_map( 'strval', (array) ( $line['key'] ?? array() ) ) );
				$line    = trim( $pattern . ' ' . $limit . ' ' . $window );
			} else {
				// "pattern limit window", whitespace or pipe separated.
				$split = preg_split( '/\s*[|]\s*|\s+/', $line );
				$parts = is_array( $split ) ? $split : array();

				$pattern = (string) ( $parts[0] ?? '' );
				$limit   = (int) ( $parts[1] ?? 0 );
				$window  = (int) ( $parts[2] ?? 0 );
				$raw_key = implode( ',', array_slice( $parts, 3 ) );
			}

			$key = self::parse_key( $raw_key );

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

			/*
			 * A key the library cannot resolve does not degrade to the address.
			 * Each unresolvable component becomes an empty string, so every
			 * request lands in the same bucket -- one visitor spending the
			 * allowance for the whole site. On a login form that is a lockout
			 * anybody can trigger.
			 */
			$unknown = self::unknown_key_components( $key );

			if ( array() !== $unknown ) {
				$errors['paths'] = sprintf(
					/* translators: 1: the rejected components, 2: the pattern. */
					__( '%1$s is not something a limit can count by, on %2$s. Every request would share one count, so one visitor could spend the allowance for everybody. Use client_ip, rule_pattern, path, method, host, scheme, port or query, or header., post., cookie. or query. followed by a name.', 'basic-firewall' ),
					implode( ', ', $unknown ),
					$pattern
				);

				continue;
			}

			/*
			 * Within one rule only the first line whose pattern matches a
			 * request is used, so a second line with the same pattern is never
			 * reached. The obvious way to pair an account limit with an address
			 * limit -- two lines for /wp-login.php -- is exactly this, and it
			 * leaves whichever line comes second doing nothing.
			 */
			if ( in_array( $pattern, array_column( $paths, 'pattern' ), true ) ) {
				$errors['paths'] = sprintf(
					/* translators: %s: the pattern. */
					__( '%s is listed twice. Only the first line whose pattern matches a request is ever used, so the second would never apply. To count an account and an address on the same pattern, put the second limit in a rate limit rule of its own.', 'basic-firewall' ),
					$pattern
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

		return array(
			'paths'                => $paths,
			'default_limit'        => max( 1, (int) ( $settings['default_limit'] ?? 60 ) ),
			'default_window'       => max( 1, (int) ( $settings['default_window'] ?? 60 ) ),
			'limit_unlisted_paths' => ! empty( $settings['limit_unlisted_paths'] ),
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

			/*
			 * `storage_table`, which DatabaseRateLimitStorage reads. This wrote
			 * `storage-table`, which it does not, so every database-backed rate
			 * limit counted into the library's default `firewall_rate_limit_storage`
			 * -- unprefixed, so shared by every site in the database, and not a
			 * table the uninstaller knows about.
			 *
			 * Prefixed only when the table lives in WordPress's own database. A
			 * supplied DSN points at a schema somebody named themselves, and
			 * prefixing it would rename a table they created.
			 */
			$compiled['config']['storage_table'] = 'wordpress' === $source
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
	 * What the Redis password belongs with.
	 *
	 * Read by Secret_Paths, so an import that points the counters at another
	 * Redis does not send this site's password there. The DSN carries its own
	 * host, so it is bound to nothing.
	 *
	 * @return array<string, list<string>>
	 */
	public function secret_bindings(): array {
		return array(
			'storage.redis_password' => array( 'storage.backend', 'storage.redis_host', 'storage.redis_port' ),
		);
	}

	/**
	 * The stored limits as the lines the screen reads them back from.
	 *
	 * `pattern requests seconds`, and the key as a fourth field when one is
	 * named -- the inverse of what validate_settings() reads, so rendering and
	 * posting back stores exactly what was there.
	 *
	 * @param mixed $value The stored `paths`: maps, or lines stored as typed.
	 */
	public static function limit_lines( $value ): string {
		$lines = array();

		foreach ( self::path_lines( $value ) as $path ) {
			if ( is_string( $path ) ) {
				$lines[] = $path;

				continue;
			}

			$key = array_values( array_map( 'strval', (array) ( $path['key'] ?? array() ) ) );

			$lines[] = trim(
				sprintf(
					'%s %d %d %s',
					(string) ( $path['pattern'] ?? '' ),
					(int) ( $path['limit'] ?? 0 ),
					(int) ( $path['window'] ?? 0 ),
					implode( ',', $key )
				)
			);
		}

		return implode( "\n", $lines );
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
					array( self::class, 'normalise_key_component' ),
					explode( ',', $value )
				),
				static fn ( string $part ): bool => '' !== $part
			)
		);
	}

	/**
	 * One key component, spelled the way the library reads it.
	 *
	 * Mirrors `RateLimit::normaliseComponent()` in kanopi/firewall 2.33.2. The
	 * prefix is forgiven its case, and so is a header name, which HTTP makes
	 * case-insensitive. A POST, cookie or query name is not: it is case-sensitive
	 * everywhere that reads it, so `post.userName` keeps its capital or it names
	 * a field that is never there -- every request would resolve to the same
	 * empty value and share one count.
	 *
	 * Before 2.33.2 the library lower-cased every component, and this plugin
	 * refused a capitalised POST, cookie or query name rather than store one
	 * that could not work. Every key stored under that rule is lower case
	 * already, and reads exactly as it did.
	 *
	 * @param string $component As typed.
	 */
	public static function normalise_key_component( string $component ): string {
		$component = trim( $component );
		$dot       = strpos( $component, '.' );

		if ( false === $dot ) {
			return strtolower( $component );
		}

		$prefix = strtolower( substr( $component, 0, $dot ) );
		$name   = substr( $component, $dot + 1 );

		return $prefix . '.' . ( 'header' === $prefix ? strtolower( $name ) : $name );
	}

	/**
	 * The components the library could not resolve against any request.
	 *
	 * @param list<string> $components Parsed, normalised components.
	 *
	 * @return list<string>
	 */
	public static function unknown_key_components( array $components ): array {
		$unknown = array();

		foreach ( $components as $component ) {
			if ( in_array( $component, self::KEY_ATOMS, true ) ) {
				continue;
			}

			foreach ( self::KEY_PREFIXES as $prefix ) {
				if ( 0 === strpos( $component, $prefix . '.' ) && strlen( $component ) > strlen( $prefix ) + 1 ) {
					continue 2;
				}
			}

			$unknown[] = $component;
		}

		return $unknown;
	}

	/**
	 * Whether a limit counts something other than the client address.
	 *
	 * A key that includes `client_ip` is still address-keyed as far as banning
	 * goes: the library withholds the offense only when the address is not
	 * part of what was counted.
	 *
	 * @param list<string> $components Parsed components; empty for the default.
	 */
	public static function counts_an_identity( array $components ): bool {
		return array() !== $components && ! in_array( 'client_ip', $components, true );
	}

	/**
	 * The stored limits of a rule, each read into a map.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<array{pattern: string, limit: int, window: int, key: list<string>}>
	 */
	public static function limits( array $settings ): array {
		$limits = array();

		foreach ( (array) ( $settings['paths'] ?? array() ) as $path ) {
			if ( is_string( $path ) ) {
				$path = self::parse_path_line( $path );
			}

			if ( ! is_array( $path ) || '' === (string) ( $path['pattern'] ?? '' ) ) {
				continue;
			}

			$limits[] = array(
				'pattern' => (string) $path['pattern'],
				'limit'   => (int) ( $path['limit'] ?? 0 ),
				'window'  => (int) ( $path['window'] ?? 0 ),
				'key'     => self::parse_key( implode( ',', array_map( 'strval', (array) ( $path['key'] ?? array() ) ) ) ),
			);
		}

		return $limits;
	}

	/**
	 * The regular expression the library matches a limit's pattern with.
	 *
	 * Asked of the library itself -- `RateLimit::patternToRegex()`, public
	 * from kanopi/firewall 2.35.1, which this plugin requires -- so a check
	 * made here cannot disagree with the limit that runs: an exact or wildcard
	 * pattern is anchored and ignores case (#50), and one written as a regular
	 * expression is used as written.
	 *
	 * @param string $pattern A limit's pattern.
	 */
	public static function pattern_regex( string $pattern ): string {
		return RateLimit::patternToRegex( $pattern );
	}

	/**
	 * Whether the library reads a limit's pattern as a regular expression.
	 *
	 * @param string $pattern A limit's pattern.
	 */
	public static function is_regex_pattern( string $pattern ): bool {
		return RateLimit::isRegexPattern( $pattern );
	}

	/**
	 * Whether a limit's pattern takes a request for a path.
	 *
	 * @param string $pattern A limit's pattern.
	 * @param string $path    A request path.
	 */
	public static function pattern_matches( string $pattern, string $path ): bool {
		// A pattern the library would warn about and skip matches nothing here either.
		return 1 === @preg_match( self::pattern_regex( $pattern ), $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- an invalid stored pattern is a no, not a warning on a status screen.
	}

	/**
	 * The earlier pattern that stops this one from ever running, if one certainly does.
	 *
	 * A rate limit uses the first line whose pattern matches, so a later line
	 * never runs when an earlier pattern matches every path it covers. The
	 * rules are the library's lint's (`ConfigLinter::shadowedBy()`,
	 * kanopi/firewall 2.35.1), so the rule screen and `firewall-check --lint`
	 * agree, and reported only where that is certain:
	 *
	 * - a later exact path is covered by any earlier exact or wildcard
	 *   pattern that matches it, tested with the regex the limit itself runs
	 *   (`/log*` before `/login`, and `/login` before `/LOGIN`, since patterns
	 *   ignore case);
	 * - a later wildcard is covered by an earlier identical one, ignoring
	 *   case, or an earlier single trailing `*` whose prefix it starts with
	 *   (`/api*` before `/api/v1/*`);
	 * - a pattern written as a regular expression is left alone on either
	 *   side: whether one arbitrary regex covers another cannot be decided.
	 *
	 * @param string       $pattern The line's pattern.
	 * @param list<string> $earlier The patterns before it in the same rule.
	 */
	public static function shadowed_by( string $pattern, array $earlier ): ?string {
		if ( self::is_regex_pattern( $pattern ) ) {
			return null;
		}

		foreach ( $earlier as $candidate ) {
			if ( self::is_regex_pattern( $candidate ) ) {
				continue;
			}

			if ( ! str_contains( $pattern, '*' ) ) {
				if ( self::pattern_matches( $candidate, $pattern ) ) {
					return $candidate;
				}

				continue;
			}

			if ( 0 === strcasecmp( $candidate, $pattern ) ) {
				return $candidate;
			}

			$prefix = strtolower( substr( $candidate, 0, -1 ) );

			if ( 1 === substr_count( $candidate, '*' ) && str_ends_with( $candidate, '*' ) && str_starts_with( strtolower( $pattern ), $prefix ) ) {
				return $candidate;
			}
		}

		return null;
	}

	/**
	 * The lines of a rule that can never run, each with the line that takes its requests.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<array{pattern: string, shadow: string}>
	 */
	public static function unreachable_limits( array $settings ): array {
		$unreachable = array();
		$earlier     = array();

		foreach ( self::limits( $settings ) as $limit ) {
			$shadow    = self::shadowed_by( $limit['pattern'], $earlier );
			$earlier[] = $limit['pattern'];

			if ( null !== $shadow ) {
				$unreachable[] = array(
					'pattern' => $limit['pattern'],
					'shadow'  => $shadow,
				);
			}
		}

		return $unreachable;
	}

	/**
	 * The lines of a rule that run: those no earlier line in the same rule covers.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<array{pattern: string, limit: int, window: int, key: list<string>}>
	 */
	private static function reachable_limits( array $settings ): array {
		$reachable = array();
		$earlier   = array();

		foreach ( self::limits( $settings ) as $limit ) {
			$shadow    = self::shadowed_by( $limit['pattern'], $earlier );
			$earlier[] = $limit['pattern'];

			if ( null === $shadow ) {
				$reachable[] = $limit;
			}
		}

		return $reachable;
	}

	/**
	 * Identity-keyed limits with no address-keyed limit beside them.
	 *
	 * The pairing the library's documentation asks for, judged the way the
	 * library's lint judges it as of kanopi/firewall 2.35.1:
	 *
	 * - **By the line that runs.** Within one rule only the first line whose
	 *   pattern matches is used, so a line an earlier one covers never runs:
	 *   it neither needs a companion nor counts as one (the rule screen
	 *   reports it as unreachable instead). A companion therefore has to be in
	 *   a different rule, and for an exact path it is whichever line of that
	 *   rule actually takes the request -- asked of the limit's own matcher,
	 *   `RateLimit::patternToRegex()` -- so `/wp-*` in another rule, keyed by
	 *   address, covers `/wp-login.php`, while an address line behind a
	 *   `/wp-*` that counts something else does not. A wildcard or regex
	 *   pattern is paired only by the same pattern, since whether one covers
	 *   another is not decidable in general.
	 * - **Ignoring case.** Rate limit patterns ignore case (2.35.0), so
	 *   `/login` in one rule and `/LOGIN` in another are one path.
	 * - **Enabled rules only.** A switched-off rule limits nothing, so it
	 *   covers nothing; switching the address limit off while debugging must
	 *   not silence the warning that brute-force protection is gone.
	 *
	 * @param array<int|string, mixed> $rules Every stored rule.
	 *
	 * @return array<string, list<string>> Rule identifier to unpaired patterns.
	 */
	public static function unpaired_identity_limits( array $rules ): array {
		$by_rule = array();

		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['enabled'] ) || 'rate_limit' !== ( $rule['type'] ?? '' ) ) {
				continue;
			}

			$by_rule[ (string) ( $rule['id'] ?? '' ) ] = self::reachable_limits( (array) ( $rule['settings'] ?? array() ) );
		}

		$unpaired = array();

		foreach ( $by_rule as $id => $limits ) {
			foreach ( $limits as $limit ) {
				if ( ! self::counts_an_identity( $limit['key'] ) ) {
					continue;
				}

				$paired = false;

				foreach ( $by_rule as $other => $others ) {
					if ( $other === $id ) {
						continue;
					}

					$runs = self::line_that_runs( $limit['pattern'], $others );

					if ( null !== $runs && ! self::counts_an_identity( $runs['key'] ) ) {
						$paired = true;

						break;
					}
				}

				if ( ! $paired ) {
					$unpaired[ $id ][] = $limit['pattern'];
				}
			}
		}

		return $unpaired;
	}

	/**
	 * The line of a rule that takes the requests a pattern names, if that can be said.
	 *
	 * For an exact path, the first line whose pattern matches it. For a
	 * wildcard or a regular expression, the same pattern, ignoring case.
	 *
	 * @param string                                                                   $pattern The pattern asked about.
	 * @param list<array{pattern: string, limit: int, window: int, key: list<string>}> $limits  Another rule's lines that run, in order.
	 *
	 * @return array{pattern: string, limit: int, window: int, key: list<string>}|null
	 */
	private static function line_that_runs( string $pattern, array $limits ): ?array {
		$exact = ! str_contains( $pattern, '*' ) && ! self::is_regex_pattern( $pattern );

		foreach ( $limits as $limit ) {
			if ( $exact ? self::pattern_matches( $limit['pattern'], $pattern ) : 0 === strcasecmp( $limit['pattern'], $pattern ) ) {
				return $limit;
			}
		}

		return null;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function check_requirements( array $settings ): array {
		$problems = parent::check_requirements( $settings );

		$keyed = array_filter( self::limits( $settings ), static fn ( array $limit ): bool => array() !== $limit['key'] );

		/*
		 * On a library older than 2.27.0 the key is ignored and the line counts
		 * the address. That is the stricter of the two, so the rule is compiled
		 * rather than skipped -- but it is not what the line says.
		 */
		if ( array() !== $keyed && ! ( new \Kanopi\BasicFirewall\Library_Capabilities() )->has_composable_rate_limit_key() ) {
			$problems[] = __( 'Some limits here name what to count, which the installed firewall library cannot do. They count the client address instead. Needs kanopi/firewall 2.27.0 or later.', 'basic-firewall' );
		}

		/*
		 * A warning, as `firewall-check --lint` gives it, rather than a
		 * refusal: the rule works, the line just does nothing. An identical
		 * pattern is still refused when the rule is saved (validate_settings());
		 * this catches the ones that differ only in case, or that an earlier
		 * wildcard takes.
		 */
		foreach ( self::unreachable_limits( $settings ) as $unreachable ) {
			$problems[] = 0 === strcasecmp( $unreachable['pattern'], $unreachable['shadow'] )
				? sprintf(
					/* translators: 1: the unreachable pattern, 2: the earlier pattern. */
					__( 'The line for %1$s never runs: %2$s comes first, and patterns ignore case, so they are the same path. Only the first line whose pattern matches a request is used. Remove one, or put the second limit in a rate limit rule of its own.', 'basic-firewall' ),
					$unreachable['pattern'],
					$unreachable['shadow']
				)
				: sprintf(
					/* translators: 1: the unreachable pattern, 2: the earlier pattern. */
					__( 'The line for %1$s never runs, because %2$s comes first and matches every request it would. Only the first line whose pattern matches a request is used. Put %1$s before %2$s, or in a rate limit rule of its own.', 'basic-firewall' ),
					$unreachable['pattern'],
					$unreachable['shadow']
				);
		}

		return $problems;
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

				$line = sprintf(
					/* translators: 1: path pattern, 2: request count, 3: window in seconds. */
					__( '%1$s — %2$d request(s) per %3$d second(s)', 'basic-firewall' ),
					(string) ( $path['pattern'] ?? '' ),
					(int) ( $path['limit'] ?? 0 ),
					(int) ( $path['window'] ?? 0 )
				);

				$key = self::parse_key( implode( ',', array_map( 'strval', (array) ( $path['key'] ?? array() ) ) ) );

				if ( array() !== $key ) {
					$line .= ' ' . sprintf(
						/* translators: %s: comma-separated key components. */
						__( 'counting %s', 'basic-firewall' ),
						implode( ', ', $key )
					);
				}

				$lines[] = $line;
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
