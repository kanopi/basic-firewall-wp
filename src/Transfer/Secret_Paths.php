<?php
/**
 * Finds the credentials in a settings document.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Transfer;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\Firewall\Source\SourceAuth;

/**
 * Resolves every path in a document that holds a credential.
 *
 * Two sources, and neither is a hand-maintained list:
 *
 * - **The schema**, for everything the plugin itself defines. A field declared
 *   `secret => true` is redacted from the day it is added rather than from the
 *   day somebody remembers to add it to the exporter.
 * - **The rule types**, each of which declares which of its own settings are
 *   credentials. That is what lets a rule type contributed through the
 *   `basic_firewall_rule_types` filter have its API key redacted without the
 *   exporter knowing the type exists.
 *
 * The distinction this class exists to draw is between a secret and a
 * *reference* to a secret. `%env(ABUSEIPDB_API_KEY)%` names an environment
 * variable; it does not contain one. Stripping it would break the receiving
 * site for no gain, so tokens survive an export intact.
 */
final class Secret_Paths {

	/**
	 * Token forms that are references rather than values.
	 *
	 * `%env(NAME)%` reads an environment variable and `%file(/path)%` reads a
	 * file. Neither holds anything sensitive: they name where the value lives.
	 */
	private const TOKEN_PATTERN = '/^%(env|file)\(.*\)%$/';

	/**
	 * Whether a value is a reference rather than a secret.
	 *
	 * @param mixed $value Stored value.
	 */
	public static function is_token( $value ): bool {
		return is_string( $value ) && 1 === preg_match( self::TOKEN_PATTERN, trim( $value ) );
	}

	/**
	 * Whether a stored credential is absent: nothing, an empty string, or an empty map.
	 *
	 * @param mixed $value Stored value.
	 */
	public static function is_empty( $value ): bool {
		return null === $value || array() === $value || ( is_string( $value ) && '' === trim( $value ) );
	}

	/**
	 * Every credential-bearing path in a document, resolved against its shape.
	 *
	 * Returned as concrete paths with list indexes filled in, so the caller can
	 * address a value directly rather than re-walking wildcards.
	 *
	 * @param array<string, mixed> $document A settings document.
	 *
	 * @return list<string>
	 */
	public static function in( array $document ): array {
		return array_map( 'strval', array_keys( self::bindings_in( $document ) ) );
	}

	/**
	 * Every credential-bearing path, with the settings the credential belongs with.
	 *
	 * The second half is what the importer checks before it keeps a stored
	 * credential that a document left out: the credential is only carried
	 * across while every setting it is bound to is unchanged. See
	 * Schema::secret_bindings().
	 *
	 * Rule types name their credentials relative to the rule's settings, with
	 * `*` for any key -- a list index, or a header name -- and those are
	 * expanded against the rule exactly as the schema's are against the
	 * document. Until they were, `sources.*.advanced.upstream.auth.token` was
	 * looked up as a literal key called `*`, found nothing, and a feed's
	 * credentials went out in every export.
	 *
	 * @param array<string, mixed> $document A settings document.
	 *
	 * @return array<string, list<string>> Concrete path => concrete paths it is bound to.
	 */
	public static function bindings_in( array $document ): array {
		$found = array();

		foreach ( Schema::secret_bindings() as $pattern => $siblings ) {
			foreach ( self::expand( $document, explode( '.', $pattern ) ) as $path ) {
				$parent = substr( $path, 0, (int) strrpos( $path, '.' ) );

				$found[ $path ] = array_map( static fn ( string $key ): string => $parent . '.' . $key, $siblings );
			}
		}

		// Rule type settings. Each type names its own.
		$registry = Plugin::instance()->rule_types();

		foreach ( (array) ( $document['rules'] ?? array() ) as $index => $rule ) {
			if ( ! is_array( $rule ) || ! is_array( $rule['settings'] ?? null ) ) {
				continue;
			}

			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			if ( null === $type ) {
				continue;
			}

			$prefix = sprintf( 'rules.%s.settings', $index );

			foreach ( self::rule_secret_patterns( $type ) as $pattern => $bound ) {
				foreach ( self::expand( $rule['settings'], explode( '.', $pattern ), $prefix ) as $path ) {
					$found[ $path ] = array_map( static fn ( string $binding ): string => self::bind( $path, $prefix, $binding ), $bound );
				}
			}
		}

		return $found;
	}

	/**
	 * Every setting in a document holding a URL that may carry a credential.
	 *
	 * @param array<string, mixed> $document A settings document.
	 *
	 * @return list<string>
	 */
	public static function urls_in( array $document ): array {
		$found    = array();
		$registry = Plugin::instance()->rule_types();

		foreach ( (array) ( $document['rules'] ?? array() ) as $index => $rule ) {
			if ( ! is_array( $rule ) || ! is_array( $rule['settings'] ?? null ) ) {
				continue;
			}

			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			if ( null === $type || ! method_exists( $type, 'source_url_settings' ) ) {
				continue;
			}

			foreach ( (array) $type->source_url_settings() as $pattern ) {
				foreach ( self::expand( $rule['settings'], explode( '.', (string) $pattern ), sprintf( 'rules.%s.settings', $index ) ) as $path ) {
					$found[] = $path;
				}
			}
		}

		return $found;
	}

	/**
	 * A URL with any credential in it replaced by `***`.
	 *
	 * The user and password of `https://user:pass@host/`, and the value of a
	 * query parameter whose name is one people put keys in -- `token`, `key`,
	 * `api_key`, `access_token`, `password`, `secret`, `signature` and the
	 * like. The list is the firewall library's own, from the redaction it
	 * applies before a URL reaches a log, so the export and the log agree on
	 * what counts. It is deliberately not cleverer than that: a key in a
	 * parameter with an innocent name, or in the path, is not recognised, and
	 * a feed that needs one belongs in the advanced block's `upstream.auth`,
	 * which is stripped whole.
	 *
	 * A local path, or anything without a host, is returned as it is.
	 *
	 * @param string $url The URL.
	 */
	public static function redact_url( string $url ): string {
		if ( self::is_token( $url ) ) {
			return $url;
		}

		return SourceAuth::redactUrl( $url );
	}

	/**
	 * The credential patterns a rule type declares, with what each is bound to.
	 *
	 * The list credentials are added for any type that takes a list, whether
	 * or not its own secret_settings() remembered to include them.
	 *
	 * @param object $type A rule type.
	 *
	 * @return array<string, list<string>>
	 */
	private static function rule_secret_patterns( object $type ): array {
		$patterns = array_fill_keys( array_map( 'strval', (array) $type->secret_settings() ), array() );

		if ( method_exists( $type, 'source_secret_bindings' ) ) {
			foreach ( (array) $type->source_secret_bindings() as $pattern => $bound ) {
				$patterns[ (string) $pattern ] = array_values( array_map( 'strval', (array) $bound ) );
			}
		}

		if ( method_exists( $type, 'secret_bindings' ) ) {
			foreach ( (array) $type->secret_bindings() as $pattern => $bound ) {
				if ( isset( $patterns[ (string) $pattern ] ) ) {
					$patterns[ (string) $pattern ] = array_values( array_map( 'strval', (array) $bound ) );
				}
			}
		}

		return $patterns;
	}

	/**
	 * Resolve a binding pattern against the concrete path of the secret it belongs to.
	 *
	 * Each `*` takes the key the secret's own path has in the same place, so
	 * the token of the second list is bound to the second list's URL.
	 *
	 * @param string $path    The secret's concrete path.
	 * @param string $prefix  The rule's settings prefix.
	 * @param string $binding The binding, relative to the rule's settings.
	 */
	private static function bind( string $path, string $prefix, string $binding ): string {
		$concrete = explode( '.', substr( $path, strlen( $prefix ) + 1 ) );
		$segments = explode( '.', $binding );

		foreach ( $segments as $position => $segment ) {
			if ( '*' === $segment && isset( $concrete[ $position ] ) ) {
				$segments[ $position ] = $concrete[ $position ];
			}
		}

		return $prefix . '.' . implode( '.', $segments );
	}

	/**
	 * Expand a wildcard path against a document.
	 *
	 * @param mixed        $node     Current node.
	 * @param list<string> $segments Remaining path segments.
	 * @param string       $prefix   Path accumulated so far.
	 *
	 * @return list<string>
	 */
	private static function expand( $node, array $segments, string $prefix = '' ): array {
		if ( array() === $segments ) {
			return '' === $prefix ? array() : array( $prefix );
		}

		if ( ! is_array( $node ) ) {
			return array();
		}

		$segment = array_shift( $segments );

		if ( '*' === $segment ) {
			$found = array();

			foreach ( array_keys( $node ) as $key ) {
				foreach ( self::expand( $node[ $key ], $segments, $prefix . '.' . $key ) as $path ) {
					$found[] = $path;
				}
			}

			return $found;
		}

		if ( ! array_key_exists( $segment, $node ) ) {
			return array();
		}

		return self::expand(
			$node[ $segment ],
			$segments,
			'' === $prefix ? $segment : $prefix . '.' . $segment
		);
	}

	/**
	 * Read a value at a dotted path.
	 *
	 * @param array<string, mixed> $document Document.
	 * @param string               $path     Dotted path.
	 *
	 * @return mixed
	 */
	public static function get( array $document, string $path ) {
		$node = $document;

		foreach ( explode( '.', $path ) as $segment ) {
			if ( ! is_array( $node ) || ! array_key_exists( $segment, $node ) ) {
				return null;
			}

			$node = $node[ $segment ];
		}

		return $node;
	}

	/**
	 * Remove the value at a dotted path.
	 *
	 * @param array<string, mixed> $document Document, by reference.
	 * @param string               $path     Dotted path.
	 */
	public static function unset_at( array &$document, string $path ): void {
		$segments = explode( '.', $path );
		$last     = array_pop( $segments );
		$cursor   = &$document;

		foreach ( $segments as $segment ) {
			if ( ! is_array( $cursor ) || ! array_key_exists( $segment, $cursor ) ) {
				return;
			}

			$cursor = &$cursor[ $segment ];
		}

		if ( is_array( $cursor ) ) {
			unset( $cursor[ $last ] );
		}

		unset( $cursor );
	}

	/**
	 * Write a value at a dotted path.
	 *
	 * @param array<string, mixed> $document Document, by reference.
	 * @param string               $path     Dotted path.
	 * @param mixed                $value    Value to write.
	 */
	public static function set( array &$document, string $path, $value ): void {
		$segments = explode( '.', $path );
		$last     = array_pop( $segments );
		$cursor   = &$document;

		foreach ( $segments as $segment ) {
			if ( ! isset( $cursor[ $segment ] ) || ! is_array( $cursor[ $segment ] ) ) {
				$cursor[ $segment ] = array();
			}

			$cursor = &$cursor[ $segment ];
		}

		$cursor[ $last ] = $value;

		unset( $cursor );
	}
}
