<?php
/**
 * Rules that name WordPress's own files without the directory it is in.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Health;

use Kanopi\BasicFirewall\RuleType\Condition_Rule_Type_Base;
use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;

/**
 * Finds rules that stop matching WordPress's own files once core has a directory of its own.
 *
 * With WordPress in its own directory (Site Address `/`, WordPress Address
 * `/wp`), a direct request for the login page reaches the rules as
 * `/wp/wp-login.php` (#32). A rule is affected only if it treats that path
 * differently from `/wp-login.php`: `path equals /wp-login.php`,
 * `path starts with /wp-admin` and a `/wp-login.php` rate limit all do, while
 * `ends with /wp-login.php` and `contains /wp-admin/` match both and need no
 * change. So rather than looking for the text, each condition and limit is
 * asked whether it takes a bare core path and not the same path with the
 * prefix: the question the rule itself will answer on this site.
 *
 * Until kanopi/firewall 2.35.0 the library's presets were written for
 * WordPress at the root, and Site Health flagged every enabled one (#45).
 * `wordpress.yml` and `search-bots.yml` now match WordPress's paths at any
 * depth, so presets are no longer checked by their text. Only a preset's rate
 * limits are asked, the same question as a rule's: a rate limit pattern is
 * anchored, and `rate-limiting.yml` still names `/wp-login.php` at the root.
 *
 * WordPress-free, so it is unit-tested with plain arrays.
 */
final class Unprefixed_Core_Paths {

	/**
	 * Requests for WordPress's own files, as they reach the rules at the root.
	 *
	 * The admin appears as the directory and as a screen, so a condition on
	 * either shape is asked about.
	 */
	public const CORE_PATHS = array( '/wp-login.php', '/xmlrpc.php', '/wp-cron.php', '/wp-admin/', '/wp-admin/index.php' );

	/**
	 * The site's own enabled rules that miss a core file behind the prefix.
	 *
	 * Referenced lists are not read: their entries arrive at refresh time,
	 * from somebody else's file. The Advanced YAML is not read either; it is
	 * the library's own format, and a rule there is the library's to lint.
	 *
	 * @param array<int|string, mixed> $rules  Every stored rule.
	 * @param string                   $prefix WordPress's directory, e.g. `/wp`.
	 *
	 * @return list<array{rule: string, label: string, value: string}> One entry per offending condition or limit.
	 */
	public static function in_rules( array $rules, string $prefix ): array {
		$found = array();

		if ( '' === $prefix ) {
			return $found;
		}

		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['enabled'] ) ) {
				continue;
			}

			$settings = is_array( $rule['settings'] ?? null ) ? $rule['settings'] : array();
			$id       = (string) ( $rule['id'] ?? '' );
			$label    = (string) ( $rule['label'] ?? $id );

			if ( 'rate_limit' === ( $rule['type'] ?? '' ) ) {
				foreach ( Rate_Limit::limits( $settings ) as $limit ) {
					if ( self::limit_misses( $limit['pattern'], $prefix ) ) {
						$found[] = array(
							'rule'  => $id,
							'label' => $label,
							'value' => $limit['pattern'],
						);
					}
				}

				continue;
			}

			foreach ( (array) ( $settings['conditions'] ?? array() ) as $condition ) {
				if ( is_array( $condition ) && 'path' === ( $condition['variable'] ?? '' ) && self::condition_misses( $condition, $prefix ) ) {
					$found[] = array(
						'rule'  => $id,
						'label' => $label,
						'value' => trim( (string) ( $condition['operator'] ?? 'equals' ) . ' ' . (string) ( $condition['value'] ?? '' ) ),
					);
				}
			}
		}

		return $found;
	}

	/**
	 * The rate limit patterns in parsed preset files that miss a core file behind the prefix.
	 *
	 * @param list<array<mixed>> $presets Each enabled preset, parsed.
	 * @param string             $prefix  WordPress's directory, e.g. `/wp`.
	 *
	 * @return list<string> The patterns.
	 */
	public static function in_preset_rate_limits( array $presets, string $prefix ): array {
		$found = array();

		if ( '' === $prefix ) {
			return $found;
		}

		foreach ( $presets as $preset ) {
			foreach ( (array) ( $preset['plugins'] ?? array() ) as $plugin ) {
				if ( ! is_array( $plugin ) || ! is_string( $plugin['plugin'] ?? null ) || 'RateLimit' !== substr( $plugin['plugin'], -9 ) ) {
					continue;
				}

				if ( false === ( $plugin['enable'] ?? true ) ) {
					continue;
				}

				foreach ( (array) ( $plugin['config'] ?? array() ) as $entry ) {
					$pattern = is_array( $entry ) && is_string( $entry['path'] ?? null ) ? $entry['path'] : '';

					if ( '' !== $pattern && self::limit_misses( $pattern, $prefix ) ) {
						$found[] = $pattern;
					}
				}
			}
		}

		return array_values( array_unique( $found ) );
	}

	/**
	 * Whether a rate limit pattern takes a bare core path and not the prefixed one.
	 *
	 * @param string $pattern The limit's pattern.
	 * @param string $prefix  WordPress's directory.
	 */
	public static function limit_misses( string $pattern, string $prefix ): bool {
		foreach ( self::CORE_PATHS as $path ) {
			if ( Rate_Limit::pattern_matches( $pattern, $path ) && ! Rate_Limit::pattern_matches( $pattern, $prefix . $path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a path condition takes a bare core path and not the prefixed one.
	 *
	 * Asked of the condition's positive form: `is not equal to /wp-login.php`
	 * was written to leave the login page out, and on this layout it leaves
	 * nothing out, which is the same mistake the other way round.
	 *
	 * @param array<string, mixed> $condition A stored condition.
	 * @param string               $prefix    WordPress's directory.
	 */
	public static function condition_misses( array $condition, string $prefix ): bool {
		foreach ( self::CORE_PATHS as $path ) {
			if ( true === self::compares( $condition, $path ) && false === self::compares( $condition, $prefix . $path ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The positive form of a path condition, applied to a path, or null for an operator not modelled.
	 *
	 * Mirrors what the plugin compiles and the library evaluates: text
	 * operators ignore case unless the condition says otherwise, `is one of`
	 * is a comma-separated list of exact paths, and a regular expression
	 * carries its case in its own flag.
	 *
	 * @param array<string, mixed> $condition A stored condition.
	 * @param string               $path      A request path.
	 */
	private static function compares( array $condition, string $path ): ?bool {
		$operator  = (string) ( $condition['operator'] ?? 'equals' );
		$value     = trim( (string) ( $condition['value'] ?? '' ) );
		$sensitive = ! empty( $condition['case_sensitive'] );

		if ( '' === $value ) {
			return null;
		}

		$operator = array(
			'not_equals'   => 'equals',
			'not_contains' => 'contains',
		)[ $operator ] ?? $operator;

		if ( 'regex' === $operator ) {
			$regex = Condition_Rule_Type_Base::assemble_regex( $value, $sensitive );

			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a pattern that does not compile matches nothing; the rule screen reports it.
			return '' === $regex ? null : 1 === @preg_match( $regex, $path );
		}

		$subject = $sensitive ? $path : strtolower( $path );
		$needle  = $sensitive ? $value : strtolower( $value );

		return match ( $operator ) {
			'equals'      => $subject === $needle,
			'in'          => in_array( $subject, array_map( 'trim', explode( ',', $needle ) ), true ),
			'starts_with' => str_starts_with( $subject, $needle ),
			'ends_with'   => str_ends_with( $subject, $needle ),
			'contains'    => str_contains( $subject, $needle ),
			default       => null,
		};
	}
}
