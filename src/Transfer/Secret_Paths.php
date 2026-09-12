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
		$paths = array();

		foreach ( Schema::secret_paths() as $pattern ) {
			foreach ( self::expand( $document, explode( '.', $pattern ) ) as $path ) {
				$paths[] = $path;
			}
		}

		// Rule type settings. Each type names its own.
		$registry = Plugin::instance()->rule_types();

		foreach ( (array) ( $document['rules'] ?? array() ) as $index => $rule ) {
			if ( ! is_array( $rule ) ) {
				continue;
			}

			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			if ( null === $type ) {
				continue;
			}

			foreach ( $type->secret_settings() as $relative ) {
				$paths[] = sprintf( 'rules.%s.settings.%s', $index, $relative );
			}
		}

		return array_values( array_unique( $paths ) );
	}

	/**
	 * Expand a wildcard path against a document.
	 *
	 * @param mixed         $node     Current node.
	 * @param list<string>  $segments Remaining path segments.
	 * @param string        $prefix   Path accumulated so far.
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
