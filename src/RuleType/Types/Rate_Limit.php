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
				'file'              => 'private://ratelimit.data',
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
	 *
	 * @param array $settings Described by the interface.
	 * @param array $errors Described by the interface.
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$paths = array();

		foreach ( self::lines_to_list( $settings['paths'] ?? array() ) as $line ) {
			// "pattern limit window", whitespace or pipe separated.
			$split = preg_split( '/\s*[|]\s*|\s+/', $line );
			$parts = is_array( $split ) ? $split : array();

			$pattern = (string) ( $parts[0] ?? '' );
			$limit   = (int) ( $parts[1] ?? 0 );
			$window  = (int) ( $parts[2] ?? 0 );

			if ( '' === $pattern || $limit < 1 || $window < 1 ) {
				$errors['paths'] = sprintf(
					/* translators: %s: the rejected line. */
					__( '%s is not a limit. Write one per line, as "pattern requests seconds" — for example "/wp-login.php 5 300".', 'basic-firewall' ),
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
				'file'              => trim( (string) ( $storage['file'] ?? 'private://ratelimit.data' ) ),
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
	 * @param array $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry    = $this->base_entry( $rule );
		$settings = $rule['settings'] ?? array();

		$limits = array();

		foreach ( $settings['paths'] ?? array() as $path ) {
			$limits[ (string) $path['pattern'] ] = array(
				'limit'  => (int) $path['limit'],
				'window' => (int) $path['window'],
			);
		}

		$config = array(
			'limits'               => $limits,
			'default_limit'        => (int) ( $settings['default_limit'] ?? 60 ),
			'default_window'       => (int) ( $settings['default_window'] ?? 60 ),
			'status_code'          => (int) ( $settings['status_code'] ?? 429 ),

			/*
			 * Written explicitly rather than omitted. The library's own default
			 * here caps the entire site with the fallback limit, and a compiled
			 * file that says what is happening is worth more than one that
			 * depends on a default that can move underneath it.
			 */
			'limit_unlisted_paths' => ! empty( $settings['limit_unlisted_paths'] ),
		);

		$entry['config'] = $config;

		$storage  = is_array( $settings['storage'] ?? null ) ? $settings['storage'] : array();
		$metadata = $entry['metadata'] ?? array();

		$metadata['storage'] = $this->compile_storage( $storage );

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
			$compiled['config']['storage_file'] = Plugin::instance()->paths()->resolve(
				(string) ( $storage['file'] ?? 'private://ratelimit.data' )
			);

			return $compiled;
		}

		if ( 'database' === $backend ) {
			$source = (string) ( $storage['connection_source'] ?? 'wordpress' );
			$table  = (string) ( $storage['table'] ?? 'basic_firewall_ratelimit' );

			// Prefixed only when the table lives in WordPress's own database. A
			// supplied DSN points at a schema somebody named themselves, and
			// prefixing it would rename a table they created.
			$compiled['config']['table'] = 'wordpress' === $source
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
			$compiled['config'] = array(
				'host' => (string) ( $storage['redis_host'] ?? '127.0.0.1' ),
				'port' => (int) ( $storage['redis_port'] ?? 6379 ),
			);

			if ( '' !== (string) ( $storage['redis_password'] ?? '' ) ) {
				$compiled['config']['password'] = (string) $storage['redis_password'];
			}

			/*
			 * The library defaults its Redis keys to a bare `ratelimit:`, so
			 * sibling sites sharing one Redis instance count each other's
			 * requests. A discriminator is inserted unless one was supplied.
			 */
			$prefix = trim( (string) ( $storage['key_prefix'] ?? '' ) );

			$compiled['config']['key_prefix'] = '' !== $prefix ? $prefix : $credentials->rate_limit_key_prefix();
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
	 * {@inheritDoc}
	 *
	 * @param array $settings Described by the interface.
	 */
	public function summarize( array $settings ): array {
		$paths = $settings['paths'] ?? array();

		if ( array() === $paths ) {
			$lines = array( __( 'No patterns listed.', 'basic-firewall' ) );
		} else {
			$lines = array();

			foreach ( array_slice( $paths, 0, 5 ) as $path ) {
				$lines[] = sprintf(
					/* translators: 1: path pattern, 2: request count, 3: window in seconds. */
					__( '%1$s — %2$d request(s) per %3$d second(s)', 'basic-firewall' ),
					(string) $path['pattern'],
					(int) $path['limit'],
					(int) $path['window']
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
