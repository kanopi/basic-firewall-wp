<?php
/**
 * Validates and coerces a settings document against the schema.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

/**
 * Walks a settings array against the schema, coercing and reporting.
 *
 * Two properties matter more than completeness here.
 *
 * **It always returns a usable document.** Every value that fails validation
 * falls back to its schema default and the failure is reported alongside. A
 * validator that refused to produce a result would take the firewall down over
 * a single bad key, and this plugin's whole failure posture is the opposite of
 * that: fail open, report loudly.
 *
 * **Unknown keys are preserved, not dropped.** A rule type contributed through
 * the `basic_firewall_rule_types` filter owns its own `settings` sub-tree, and
 * a site that downgrades the plugin, or disables the module supplying a type,
 * must not have that configuration quietly deleted by the first save that
 * follows. Drupal's typed config would reject them; here the cost of rejecting
 * is silent data loss, so the trade goes the other way and unknown keys ride
 * along untouched.
 */
final class Validator {

	/**
	 * Problems found during the last run.
	 *
	 * @var list<array{path: string, message: string}>
	 */
	private array $errors = array();

	/**
	 * Validate and coerce a document.
	 *
	 * @param array<string, mixed>      $values Raw settings.
	 * @param array<string, mixed>|null $schema Schema node, defaults to the whole tree.
	 *
	 * @return array<string, mixed> The coerced document.
	 */
	public function validate( array $values, ?array $schema = null ): array {
		$this->errors = array();
		$schema       = $schema ?? Schema::definition();

		$result = $this->walk( $values, $schema, '' );

		return is_array( $result ) ? $result : array();
	}

	/**
	 * Problems found by the last validate() call.
	 *
	 * @return list<array{path: string, message: string}>
	 */
	public function errors(): array {
		return $this->errors;
	}

	/**
	 * Whether the last validate() call found nothing wrong.
	 */
	public function is_valid(): bool {
		return array() === $this->errors;
	}

	/**
	 * Coerce one value against one schema node.
	 *
	 * @param mixed                $value  Incoming value.
	 * @param array<string, mixed> $node   Schema node.
	 * @param string               $path   Dotted path, for error reporting.
	 *
	 * @return mixed
	 */
	private function walk( $value, array $node, string $path ) {
		$type    = (string) ( $node['type'] ?? 'string' );
		$default = $node['default'] ?? null;

		switch ( $type ) {
			case 'map':
				return $this->walk_map( $value, $node, $path );

			case 'list':
				return $this->walk_list( $value, $node, $path );

			case 'raw':
				// Owned and validated by a rule type. Passed through as-is.
				return is_array( $value ) ? $value : ( $default ?? array() );

			case 'bool':
				return $this->to_bool( $value );

			case 'int':
				return $this->to_int( $value, $node, $path, (int) $default );

			case 'float':
				return $this->to_float( $value, $node, $path, (float) $default );

			case 'text':
			case 'string':
			default:
				return $this->to_string( $value, $node, $path, (string) $default );
		}
	}

	/**
	 * Coerce a mapping.
	 *
	 * @param mixed                $value Incoming value.
	 * @param array<string, mixed> $node  Schema node.
	 * @param string               $path  Dotted path.
	 *
	 * @return array<string, mixed>
	 */
	private function walk_map( $value, array $node, string $path ): array {
		$children = $node['children'] ?? array();

		if ( ! is_array( $value ) ) {
			if ( null !== $value ) {
				$this->error( $path, 'Expected a set of values.' );
			}

			$value = array();
		}

		$out = array();

		foreach ( $children as $key => $child ) {
			$child_path = '' === $path ? (string) $key : $path . '.' . $key;

			$out[ $key ] = array_key_exists( $key, $value )
				? $this->walk( $value[ $key ], $child, $child_path )
				: $this->default_for( $child );
		}

		// Keys the schema does not know about survive. See the class docblock.
		foreach ( $value as $key => $extra ) {
			if ( ! array_key_exists( $key, $children ) ) {
				$out[ $key ] = $extra;
			}
		}

		return $out;
	}

	/**
	 * Coerce a sequence.
	 *
	 * @param mixed                $value Incoming value.
	 * @param array<string, mixed> $node  Schema node.
	 * @param string               $path  Dotted path.
	 *
	 * @return array<int|string, mixed>
	 */
	private function walk_list( $value, array $node, string $path ): array {
		if ( ! is_array( $value ) ) {
			if ( null !== $value ) {
				$this->error( $path, 'Expected a list.' );
			}

			return $node['default'] ?? array();
		}

		$of  = $node['of'] ?? array( 'type' => 'string' );
		$out = array();

		foreach ( $value as $key => $item ) {
			$out[ $key ] = $this->walk( $item, $of, $path . '.' . $key );
		}

		return $out;
	}

	/**
	 * The default for a node, recursing into maps.
	 *
	 * @param array<string, mixed> $node Schema node.
	 *
	 * @return mixed
	 */
	private function default_for( array $node ) {
		if ( 'map' === ( $node['type'] ?? '' ) ) {
			$out = array();

			foreach ( $node['children'] ?? array() as $key => $child ) {
				$out[ $key ] = $this->default_for( $child );
			}

			return $out;
		}

		return $node['default'] ?? null;
	}

	/**
	 * Coerce to bool.
	 *
	 * Checkbox values arrive from HTML as '1', '0', 'on' or absent, and from an
	 * imported document as real booleans or as the YAML spellings. Everything
	 * that is unambiguously false is false; anything else is true.
	 *
	 * @param mixed $value Incoming value.
	 */
	private function to_bool( $value ): bool {
		if ( is_bool( $value ) ) {
			return $value;
		}

		if ( is_string( $value ) ) {
			return ! in_array( strtolower( trim( $value ) ), array( '', '0', 'false', 'no', 'off' ), true );
		}

		return (bool) $value;
	}

	/**
	 * Coerce to int, honouring min and max.
	 *
	 * @param mixed                $value   Incoming value.
	 * @param array<string, mixed> $node    Schema node.
	 * @param string               $path    Dotted path.
	 * @param int                  $fallback Fallback value.
	 */
	private function to_int( $value, array $node, string $path, int $fallback ): int {
		if ( is_bool( $value ) || ! is_scalar( $value ) || ( is_string( $value ) && ! is_numeric( trim( $value ) ) ) ) {
			if ( null !== $value && '' !== $value ) {
				$this->error( $path, 'Expected a whole number.' );
			}

			return $fallback;
		}

		$number = (int) $value;

		if ( isset( $node['min'] ) && $number < (int) $node['min'] ) {
			$this->error( $path, sprintf( 'Must be %d or greater.', (int) $node['min'] ) );

			return $fallback;
		}

		if ( isset( $node['max'] ) && $number > (int) $node['max'] ) {
			$this->error( $path, sprintf( 'Must be %d or less.', (int) $node['max'] ) );

			return $fallback;
		}

		return $number;
	}

	/**
	 * Coerce to float, honouring min and max.
	 *
	 * @param mixed                $value   Incoming value.
	 * @param array<string, mixed> $node    Schema node.
	 * @param string               $path    Dotted path.
	 * @param float                $fallback Fallback value.
	 */
	private function to_float( $value, array $node, string $path, float $fallback ): float {
		if ( is_bool( $value ) || ! is_scalar( $value ) || ( is_string( $value ) && ! is_numeric( trim( $value ) ) ) ) {
			if ( null !== $value && '' !== $value ) {
				$this->error( $path, 'Expected a number.' );
			}

			return $fallback;
		}

		$number = (float) $value;

		if ( isset( $node['min'] ) && $number < (float) $node['min'] ) {
			$this->error( $path, sprintf( 'Must be %s or greater.', (string) $node['min'] ) );

			return $fallback;
		}

		if ( isset( $node['max'] ) && $number > (float) $node['max'] ) {
			$this->error( $path, sprintf( 'Must be %s or less.', (string) $node['max'] ) );

			return $fallback;
		}

		return $number;
	}

	/**
	 * Coerce to string, honouring a closed choice list.
	 *
	 * @param mixed                $value   Incoming value.
	 * @param array<string, mixed> $node    Schema node.
	 * @param string               $path    Dotted path.
	 * @param string               $fallback Fallback value.
	 */
	private function to_string( $value, array $node, string $path, string $fallback ): string {
		if ( is_array( $value ) || is_object( $value ) ) {
			$this->error( $path, 'Expected text.' );

			return $fallback;
		}

		if ( is_bool( $value ) ) {
			/*
			 * YAML reads `no` as boolean false, and `behind_proxy: no` is a real
			 * and meaningful value here. Spelling it back out rather than
			 * stringifying to '' keeps an imported document meaning what it said.
			 */
			$value = $value ? 'yes' : 'no';
		}

		$string = null === $value ? '' : trim( (string) $value );

		if ( isset( $node['choices'] ) && is_array( $node['choices'] ) && ! in_array( $string, $node['choices'], true ) ) {
			$this->error(
				$path,
				sprintf( 'Must be one of: %s.', implode( ', ', array_map( 'strval', $node['choices'] ) ) )
			);

			return $fallback;
		}

		return $string;
	}

	/**
	 * Record a problem.
	 *
	 * @param string $path    Dotted path.
	 * @param string $message Human-readable problem.
	 */
	private function error( string $path, string $message ): void {
		$this->errors[] = array(
			'path'    => $path,
			'message' => $message,
		);
	}
}
