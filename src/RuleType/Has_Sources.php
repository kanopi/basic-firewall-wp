<?php
/**
 * Referenced lists, shared by the rule types that can take one.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Paths;
use Symfony\Component\Yaml\Yaml;

/**
 * Everything about a referenced list that does not depend on the rule type.
 *
 * Fetching, shaping, validating and refreshing a published list is the same
 * problem whether the entries are addresses or user agent fragments. What
 * differs is only the last step: an IP rule takes the entry as it stands, and a
 * condition rule has to turn it into a condition. That step is
 * `source_template()`, which each type answers for itself.
 *
 * Extracted when the second family needed it. The first version supported the
 * IP rule alone and said so out loud -- `Url::supports_sources()` returned
 * false with a comment explaining that its sources were a different shape. They
 * are, but not a harder one.
 */
trait Has_Sources {

	/**
	 * A day, which is what a published list is worth revalidating at.
	 *
	 * Providers move things on the order of weeks, and the refresh happens out
	 * of band rather than on the request path, so a shorter window buys nothing
	 * and a longer one risks a stale allowlist.
	 */
	public const DEFAULT_SOURCE_TTL = 86400;

	/**
	 * One referenced list, with everything unset.
	 *
	 * @return array<string, mixed>
	 */
	public static function source_defaults(): array {
		return array(
			'name'        => '',
			'url'         => '',
			'format'      => '',
			'compression' => '',
			'select'      => '',
			'template'    => '',
			'variable'    => '',
			'operator'    => 'contains',
			'negate'      => false,
			'validate'    => static::source_validator_default(),
			'ttl'         => self::DEFAULT_SOURCE_TTL,
			'on_error'    => 'last_known_good',
			'max_delta'   => '',
			'max_size'    => '',
			'checksum'    => '',
			'required'    => false,
			'advanced'    => array(),
		);
	}

	/**
	 * The shape entries are asserted to have, unless told otherwise.
	 *
	 * Blank for most types, because a list of crawler names or paths is only
	 * ever "some non-empty string" and asserting more would reject entries the
	 * rule can use. The IP rule overrides it: there, an entry that is not an
	 * address is one the plugin cannot act on, and catching that at refresh is
	 * the difference between a rejected list and a list that silently matches
	 * nothing.
	 */
	public static function source_validator_default(): string {
		return '';
	}

	/**
	 * Formats the library can decode. Blank means "work it out from the URL".
	 *
	 * @return array<string, string>
	 */
	public static function formats(): array {
		return array(
			''       => __( 'Detect from the URL', 'basic-firewall' ),
			'txt'    => __( 'Plain text — one entry per line', 'basic-firewall' ),
			'json'   => __( 'JSON', 'basic-firewall' ),
			'ndjson' => __( 'NDJSON — one JSON object per line', 'basic-firewall' ),
			'yaml'   => __( 'YAML', 'basic-firewall' ),
			'xml'    => __( 'XML', 'basic-firewall' ),
			'csv'    => __( 'CSV', 'basic-firewall' ),
			'tsv'    => __( 'TSV', 'basic-firewall' ),
		);
	}

	/**
	 * Compressions the library can unwrap.
	 *
	 * @return array<string, string>
	 */
	public static function compressions(): array {
		return array(
			''     => __( 'Detect from the URL', 'basic-firewall' ),
			'none' => __( 'None', 'basic-firewall' ),
			'gzip' => __( 'gzip', 'basic-firewall' ),
		);
	}

	/**
	 * Shapes an entry can be asserted to conform to.
	 *
	 * @return array<string, string>
	 */
	public static function validators(): array {
		return array(
			''       => __( 'Anything non-empty', 'basic-firewall' ),
			'cidr'   => __( 'An address, CIDR block or range', 'basic-firewall' ),
			'ip'     => __( 'A single address only', 'basic-firewall' ),
			'regex'  => __( 'A regular expression', 'basic-firewall' ),
			'string' => __( 'Any non-empty string', 'basic-firewall' ),
		);
	}

	/**
	 * Digest algorithms a sidecar checksum may use.
	 *
	 * The library offers no md5 or sha1 on purpose: a checksum a forger can
	 * collide is a checksum that says nothing, and offering it would invite
	 * somebody to rely on it.
	 *
	 * @return array<string, string>
	 */
	public static function checksums(): array {
		return array(
			''       => __( 'None — the bytes are not checked', 'basic-firewall' ),
			'sha256' => __( 'SHA-256 sidecar', 'basic-firewall' ),
			'sha384' => __( 'SHA-384 sidecar', 'basic-firewall' ),
			'sha512' => __( 'SHA-512 sidecar', 'basic-firewall' ),
		);
	}

	/**
	 * What to do when a list cannot be fetched.
	 *
	 * The library's three policies, described in terms of what happens to
	 * traffic rather than to the fetch.
	 *
	 * @return array<string, string>
	 */
	public static function error_policies(): array {
		return array(
			'last_known_good' => __( 'Keep using the last copy that worked (recommended)', 'basic-firewall' ),
			'fail_open'       => __( 'Drop the list from this rule until the fetch succeeds', 'basic-firewall' ),
			'abort'           => __( 'Refuse to start the firewall at all', 'basic-firewall' ),
		);
	}

	/**
	 * Whether a source reference is one this plugin will hand to the library.
	 *
	 * HTTP and HTTPS only, or a relative path resolved inside the private
	 * directory. An absolute path is refused deliberately: `metadata.sources`
	 * is reachable from an imported configuration document, and a source is a
	 * file the firewall reads at the web server's privilege.
	 *
	 * @param string $entry Candidate source.
	 */
	public static function is_valid_source( string $entry ): bool {
		$entry = trim( $entry );

		if ( '' === $entry ) {
			return false;
		}

		if ( 1 === preg_match( '#^https?://#i', $entry ) ) {
			return false !== filter_var( $entry, FILTER_VALIDATE_URL );
		}

		return 1 !== preg_match( '#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $entry )
			&& ! Paths::is_absolute( $entry )
			&& false === strpos( $entry, '..' );
	}

	/**
	 * Check each referenced list.
	 *
	 * A list is refused rather than stored when it cannot be fetched or its
	 * shape cannot be interpreted, because the failure mode otherwise is the
	 * one this plugin exists to prevent: a rule that saves, reports itself
	 * active, and contributes nothing.
	 *
	 * @param array<int, mixed>     $sources Submitted lists.
	 * @param array<string, string> $errors  Collected errors, by field.
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function validate_sources( array $sources, array &$errors ): array {
		$clean = array();

		foreach ( $sources as $index => $source ) {
			if ( ! is_array( $source ) ) {
				continue;
			}

			$source = array_merge( self::source_defaults(), $source );
			$url    = trim( (string) $source['url'] );

			// A wholly blank row is the empty form, not a mistake.
			if ( '' === $url ) {
				continue;
			}

			if ( ! self::is_valid_source( $url ) ) {
				$errors[ 'sources.' . $index . '.url' ] = sprintf(
					/* translators: %s: the rejected entry. */
					__( '%s is not an http(s) URL or a filename inside the private directory. An absolute path and any other scheme are refused: a list is read at the web server\'s privilege, and this setting travels in an imported configuration.', 'basic-firewall' ),
					$url
				);

				continue;
			}

			$advanced = $this->parse_advanced( $source['advanced'], (int) $index, $errors );

			if ( null === $advanced ) {
				continue;
			}

			$checksum = array_key_exists( (string) $source['checksum'], self::checksums() ) ? (string) $source['checksum'] : '';

			/*
			 * The library refuses a source declaring both, and says why: two
			 * assertions about the same bytes is a configuration somebody is
			 * midway through changing, and guessing which half they meant is
			 * how the weaker one ends up being the one that runs.
			 *
			 * Caught here because the alternative is a rule that saves and then
			 * throws when the firewall next loads -- which, depending on the
			 * error policy, is either a list that silently stops contributing
			 * or a firewall that does not start.
			 */
			if ( '' !== $checksum && isset( $advanced['signature'] ) ) {
				$errors[ 'sources.' . $index . '.checksum' ] = __( 'This list declares both a checksum and a signature, and the firewall refuses that rather than guessing which you meant. A signature already covers the bytes a checksum would, so keep the signature and set this back to none.', 'basic-firewall' );

				continue;
			}

			$delta = trim( (string) $source['max_delta'] );

			if ( '' !== $delta && ( ! is_numeric( $delta ) || (float) $delta < 0 ) ) {
				$errors[ 'sources.' . $index . '.max_delta' ] = __( 'The change limit must be a fraction such as 0.5, or blank for no limit.', 'basic-firewall' );

				$delta = '';
			}

			$clean[] = array(
				'name'        => trim( (string) $source['name'] ),
				'url'         => $url,
				'format'      => array_key_exists( (string) $source['format'], self::formats() ) ? (string) $source['format'] : '',
				'compression' => array_key_exists( (string) $source['compression'], self::compressions() ) ? (string) $source['compression'] : '',
				'select'      => trim( (string) $source['select'] ),
				'template'    => trim( (string) $source['template'] ),
				'variable'    => trim( (string) $source['variable'] ),
				'operator'    => trim( (string) $source['operator'] ),
				'negate'      => ! empty( $source['negate'] ),
				'validate'    => array_key_exists( (string) $source['validate'], self::validators() ) ? (string) $source['validate'] : '',
				'ttl'         => max( 60, (int) $source['ttl'] ),
				'on_error'    => array_key_exists( (string) $source['on_error'], self::error_policies() ) ? (string) $source['on_error'] : 'last_known_good',
				'max_delta'   => $delta,
				'max_size'    => trim( (string) $source['max_size'] ),
				'checksum'    => $checksum,
				'required'    => ! empty( $source['required'] ),
				'advanced'    => $advanced,
			);
		}

		return $clean;
	}

	/**
	 * Read the per-list advanced block, or report why it could not be read.
	 *
	 * @param mixed                 $advanced Raw YAML, or an already-parsed map.
	 * @param int                   $index    Which list, for the error key.
	 * @param array<string, string> $errors   Collected errors.
	 *
	 * @return array<string, mixed>|null Null when it could not be parsed.
	 */
	private function parse_advanced( $advanced, int $index, array &$errors ): ?array {
		if ( is_array( $advanced ) ) {
			return $advanced;
		}

		$advanced = trim( (string) $advanced );

		if ( '' === $advanced ) {
			return array();
		}

		try {
			$parsed = Yaml::parse( $advanced );
		} catch ( \Throwable $e ) {
			$errors[ 'sources.' . $index . '.advanced' ] = sprintf(
				/* translators: %s: parser error. */
				__( 'The advanced block could not be parsed, so this list was not saved: %s', 'basic-firewall' ),
				$e->getMessage()
			);

			return null;
		}

		if ( null !== $parsed && ! is_array( $parsed ) ) {
			$errors[ 'sources.' . $index . '.advanced' ] = __( 'The advanced block must describe a set of keys, such as where: or upstream:.', 'basic-firewall' );

			return null;
		}

		return is_array( $parsed ) ? $parsed : array();
	}

	/**
	 * Make a file reference absolute before handing it to the library.
	 *
	 * The opposite of what this plugin does for storage and log paths, and for
	 * a reason worth stating: those keys are on the library's own list of
	 * paths to resolve against the directory holding the config file, so
	 * expanding them here would replace what the administrator typed for no
	 * gain. `metadata.sources.*.upstream` is not on that list. A relative path
	 * left alone is resolved against whatever the process working directory
	 * happens to be -- php-fpm, WP-CLI and cron each give a different answer,
	 * and all three of them wrong -- so the list silently loads nothing and the
	 * error policy hides the reason.
	 *
	 * A URL is left exactly as it is.
	 *
	 * @param string $url The stored reference.
	 */
	private function resolve_source_url( string $url ): string {
		$url = trim( $url );

		if ( 1 === preg_match( '#^[a-zA-Z][a-zA-Z0-9+.\-]*://#', $url ) || Paths::is_absolute( $url ) ) {
			return $url;
		}

		return Plugin::instance()->paths()->resolve( $url );
	}

	/**
	 * Turn the referenced lists into the library's `metadata.sources`.
	 *
	 * Referenced rather than copied, which is the whole point. A published list
	 * changes without telling anyone; a copy pasted into a rule is correct on
	 * the day it is pasted and wrong from then on, and wrong here means either
	 * something blocked that should not be or something allowed that should
	 * not be. The firewall holds the URL and refreshes it out of band.
	 *
	 * @param array<string, mixed> $rule The rule.
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function compile_sources( array $rule ): array {
		$settings = (array) ( $rule['settings'] ?? array() );
		$sources  = array_values( (array) ( $settings['sources'] ?? array() ) );

		if ( array() === $sources ) {
			return array();
		}

		$id       = trim( (string) ( $rule['id'] ?? 'rule' ) );
		$compiled = array();

		foreach ( $sources as $index => $source ) {
			if ( ! is_array( $source ) || '' === trim( (string) ( $source['url'] ?? '' ) ) ) {
				continue;
			}

			$source = array_merge( self::source_defaults(), $source );

			$name = trim( (string) $source['name'] );

			if ( '' === $name ) {
				$name = count( $sources ) > 1 ? sprintf( '%s-%d', $id, $index + 1 ) : $id;
			}

			$advanced = is_array( $source['advanced'] ) ? $source['advanced'] : array();

			/*
			 * `upstream` is a string when it is only a URL, and a map when the
			 * advanced block adds anything to it -- auth, headers, a method, a
			 * body, a timeout. The URL from the form always wins, so the field
			 * somebody can see is never quietly overridden by the block they
			 * have to scroll to.
			 */
			$url = $this->resolve_source_url( (string) $source['url'] );

			$upstream = $advanced['upstream'] ?? null;
			$upstream = is_array( $upstream )
				? array_merge( $upstream, array( 'url' => $url ) )
				: $url;

			unset( $advanced['upstream'] );

			$entry = array(
				'name'     => $name,
				'upstream' => $upstream,
			);

			/*
			 * Every key here is the library's own spelling, which is snake_case
			 * -- `on_error` and `max_delta`, not their camelCase constructor
			 * names. A declaration is read with array keys, so the wrong
			 * spelling is not an error: it is silently ignored and the default
			 * applies, which for `on_error` means an `abort` policy quietly
			 * becoming `last_known_good`.
			 */
			foreach ( array( 'format', 'compression', 'select' ) as $key ) {
				if ( '' !== (string) $source[ $key ] ) {
					$entry[ $key ] = (string) $source[ $key ];
				}
			}

			$template = $this->source_template( $source );

			if ( null !== $template ) {
				$entry['template'] = $template;
			}

			if ( '' !== (string) $source['validate'] ) {
				$entry['validate'] = (string) $source['validate'];
			}

			$entry['ttl']      = (int) $source['ttl'];
			$entry['on_error'] = (string) $source['on_error'];

			if ( '' !== (string) $source['max_delta'] ) {
				$entry['max_delta'] = (float) $source['max_delta'];
			}

			/*
			 * A ceiling on how much may come back, which the library applies
			 * after decompression as well as on the wire -- the case that
			 * matters, since a 100 KB gzip body of ordinary repetitive list
			 * data decodes to tens of megabytes and `.gz` on a URL infers
			 * compression without anybody choosing it.
			 *
			 * Left absent, the library's own 32 MiB applies. Written only when
			 * somebody chose a different number.
			 */
			if ( '' !== (string) $source['max_size'] ) {
				$entry['upstream'] = is_array( $entry['upstream'] )
					? array_merge( $entry['upstream'], array( 'max_size' => (string) $source['max_size'] ) )
					: array(
						'url'      => (string) $entry['upstream'],
						'max_size' => (string) $source['max_size'],
					);
			}

			/*
			 * What the bytes are supposed to be.
			 *
			 * HTTPS authenticates the host and protects the transport, and says
			 * nothing about a repository that was compromised, a CDN object
			 * replaced, or a publisher who pushed the wrong file. A sidecar on
			 * the same host does not close that -- anyone who can replace the
			 * list can replace the sidecar -- which is why it is the cheap tier
			 * and a pinned-key signature, written in the advanced block, is the
			 * one that means something.
			 */
			if ( '' !== (string) $source['checksum'] ) {
				$entry['checksum'] = (string) $source['checksum'];
			}

			if ( ! empty( $source['required'] ) ) {
				$entry['required'] = true;
			}

			// Everything the form has no field for: where, header_row,
			// delimiter, comment, a nested template map.
			$compiled[] = array_merge( $entry, $advanced );
		}

		return $compiled;
	}
}
