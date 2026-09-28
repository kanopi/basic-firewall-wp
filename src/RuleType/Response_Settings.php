<?php
/**
 * The checks a redirect or a mark rule has to pass before it is worth saving.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

/**
 * What makes a redirect destination, a mark name or a mark header usable.
 *
 * Kept free of WordPress so the rule screen and the compiler can share one
 * answer and the unit suite can pin it down. The screen refuses to save what
 * fails here; the compiler refuses to emit it, which covers a document that
 * arrived by import or WP-CLI rather than through the screen. Two places
 * deciding this separately is how a rule ends up saved by one and skipped by
 * the other with nobody able to say why.
 *
 * Problems are returned as codes rather than sentences, because the two
 * callers say them differently: the screen talks to the person who typed the
 * value, the compiler to whoever reads the Status screen later.
 */
final class Response_Settings {

	/**
	 * A redirect rule with nowhere to send the visitor.
	 */
	public const REDIRECT_EMPTY = 'empty';

	/**
	 * A destination beginning `//`, which is another site written like a path.
	 */
	public const REDIRECT_OFF_SITE = 'off_site';

	/**
	 * Neither a path on this site nor an http(s) URL.
	 */
	public const REDIRECT_UNSUPPORTED = 'unsupported';

	/**
	 * What is wrong with a redirect destination, or null when nothing is.
	 *
	 * Empty is the one that matters most. The library throws a configuration
	 * exception for a redirect rule naming nowhere, at the moment the rule
	 * matches -- so the rule does not quietly do nothing, it turns every
	 * request it matches into a firewall failure, which this plugin then fails
	 * open on. The visitor the rule was written for is served as though it did
	 * not exist, a block rule below it never gets its turn on that request,
	 * and the log fills with errors instead of redirects.
	 *
	 * @param string $location The destination as typed.
	 */
	public static function redirect_problem( string $location ): ?string {
		$location = trim( $location );

		if ( '' === $location ) {
			return self::REDIRECT_EMPTY;
		}

		/*
		 * Named rather than folded into "unsupported", because it is the one
		 * that looks right. A browser reads `//evil.example/x` as another host
		 * on the current scheme, so a destination typed as a path can send the
		 * visitor off the site entirely.
		 */
		if ( str_starts_with( $location, '//' ) ) {
			return self::REDIRECT_OFF_SITE;
		}

		if ( ! str_starts_with( $location, '/' ) && 1 !== preg_match( '#^https?://#i', $location ) ) {
			return self::REDIRECT_UNSUPPORTED;
		}

		return null;
	}

	/**
	 * Whether a rule's own path conditions appear to match where it redirects.
	 *
	 * That combination is a loop the visitor experiences as a dead browser, and
	 * it is easy to write by accident on a URL rule: "send anything under
	 * /old-api to /old-api/gone". Only the obvious shapes are checked -- a
	 * positive `path` condition that equals, contains or starts the destination
	 * -- which is why the screen treats this as a warning rather than an error.
	 * A rule can legitimately redirect somewhere it also matches when something
	 * earlier in the order lets that request through.
	 *
	 * @param string                           $location   The destination.
	 * @param array<int, array<string, mixed>> $conditions The rule's conditions.
	 */
	public static function redirect_loops( string $location, array $conditions ): bool {
		$location = trim( $location );

		if ( '' === $location ) {
			return false;
		}

		foreach ( $conditions as $condition ) {
			if ( ! is_array( $condition ) || 'path' !== ( $condition['variable'] ?? '' ) || ! empty( $condition['negate'] ) ) {
				continue;
			}

			$value = trim( (string) ( $condition['value'] ?? '' ) );

			if ( '' === $value ) {
				continue;
			}

			$matches = match ( (string) ( $condition['operator'] ?? '' ) ) {
				'equals'      => 0 === strcasecmp( $value, $location ),
				'contains'    => false !== stripos( $location, $value ),
				'starts_with' => 0 === stripos( $location, $value ),
				default       => false,
			};

			if ( $matches ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a mark name can be read back out by the site's own code.
	 *
	 * The name becomes part of a request attribute key, `firewall.mark.NAME`,
	 * so a space or a dot in it produces a key nothing can address
	 * predictably. Empty is allowed: it means "use the rule identifier", which
	 * is what the library does anyway.
	 *
	 * @param string $name The name as typed.
	 */
	public static function is_mark_name( string $name ): bool {
		$name = trim( $name );

		return '' === $name || 1 === preg_match( '/^[A-Za-z0-9_-]+$/', $name );
	}

	/**
	 * Whether a header name is one a request can carry. Empty means "none".
	 *
	 * @param string $header The header as typed.
	 */
	public static function is_header_name( string $header ): bool {
		$header = trim( $header );

		return '' === $header || 1 === preg_match( '/^[A-Za-z0-9-]+$/', $header );
	}
}
