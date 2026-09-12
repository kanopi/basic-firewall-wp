<?php
/**
 * Base for rule types configured as a list of request conditions.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

/**
 * Rule types that match on a list of conditions.
 *
 * Conditions are stored and compiled in the library's **structured** format
 * rather than its `variable@operator:value` shorthand. That is deliberate. The
 * shorthand parser:
 *
 * - splits any comma-bearing value into a list without setting a match mode;
 * - mis-parses values containing `@` when no explicit operator is given;
 * - offers no way to request a case-sensitive comparison.
 *
 * The structured format has none of those problems, at the cost of being more
 * verbose in the compiled file -- which nobody hand-edits anyway.
 */
abstract class Condition_Rule_Type_Base extends Rule_Type_Base {

	/**
	 * Operators the library's evaluator supports.
	 *
	 * @var array<string, string>
	 */
	public const OPERATORS = array(
		'equals'       => 'is equal to',
		'not_equals'   => 'is not equal to',
		'contains'     => 'contains',
		'not_contains' => 'does not contain',
		'starts_with'  => 'starts with',
		'ends_with'    => 'ends with',
		'regex'        => 'matches the regular expression',
		'in'           => 'is one of',
		'gt'           => 'is greater than',
		'gte'          => 'is greater than or equal to',
		'lt'           => 'is less than',
		'lte'          => 'is less than or equal to',
		'exists'       => 'is present',
	);

	/**
	 * Operators that need no value.
	 *
	 * @var list<string>
	 */
	protected const VALUELESS_OPERATORS = array( 'exists' );

	/**
	 * The variables this type can match on.
	 *
	 * @return array<string, string> Variable name to human description.
	 */
	abstract protected function variable_options(): array;

	/**
	 * Whether a variable name outside variable_options() is allowed.
	 *
	 * True for types whose variables carry a free-form suffix, such as
	 * `header.x-anything` or `cookie.session_name`.
	 */
	protected function variables_are_free_form(): bool {
		return false;
	}

	/**
	 * Prefixes a free-form variable may use.
	 *
	 * @return list<string>
	 */
	protected function variable_prefixes(): array {
		return array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return array(
			'match_type' => 'any',
			'conditions' => array(),
		);
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed>  $settings Described by the interface.
	 * @param array<string, string> $errors Described by the interface.
	 */
	public function validate_settings( array $settings, array &$errors ): array {
		$match = (string) ( $settings['match_type'] ?? 'any' );

		$clean = array(
			'match_type' => in_array( $match, array( 'any', 'all' ), true ) ? $match : 'any',
			'conditions' => array(),
		);

		$raw = $settings['conditions'] ?? array();

		if ( ! is_array( $raw ) ) {
			$raw = array();
		}

		foreach ( array_values( $raw ) as $index => $condition ) {
			if ( ! is_array( $condition ) ) {
				continue;
			}

			$variable = trim( (string) ( $condition['variable'] ?? '' ) );
			$operator = (string) ( $condition['operator'] ?? 'equals' );
			$value    = (string) ( $condition['value'] ?? '' );

			if ( '' === $variable ) {
				// An entirely blank row is a row somebody added and did not
				// fill in. Dropping it silently is right; complaining is not.
				if ( '' === trim( $value ) ) {
					continue;
				}

				$errors[ "conditions.$index.variable" ] = __( 'Choose what this condition looks at.', 'basic-firewall' );
				continue;
			}

			if ( ! isset( self::OPERATORS[ $operator ] ) ) {
				$errors[ "conditions.$index.operator" ] = __( 'That comparison is not one the firewall can make.', 'basic-firewall' );
				continue;
			}

			if ( ! $this->variable_is_known( $variable ) ) {
				$errors[ "conditions.$index.variable" ] = sprintf(
					/* translators: %s: variable name. */
					__( '%s is not something this rule type can read. A rule on an unknown variable matches nothing.', 'basic-firewall' ),
					$variable
				);
				continue;
			}

			if ( '' === trim( $value ) && ! in_array( $operator, self::VALUELESS_OPERATORS, true ) ) {
				$errors[ "conditions.$index.value" ] = __( 'This comparison needs a value.', 'basic-firewall' );
				continue;
			}

			/*
			 * The library silently rejects an undelimited pattern, so a rule
			 * written as `^/wp-admin` saves, reports itself as active, and
			 * matches nothing at all. Caught here rather than discovered later.
			 */
			if ( 'regex' === $operator ) {
				if ( ! self::is_delimited_regex( $value ) ) {
					$errors[ "conditions.$index.value" ] = __( 'A regular expression must include its delimiters, for example #^/wp-admin# rather than ^/wp-admin. The firewall rejects an undelimited pattern, and the rule would silently match nothing.', 'basic-firewall' );
					continue;
				}

				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false === @preg_match( $value, '' ) ) {
					$errors[ "conditions.$index.value" ] = __( 'That regular expression is not valid.', 'basic-firewall' );
					continue;
				}
			}

			$clean['conditions'][] = array(
				'variable'       => $variable,
				'operator'       => $operator,
				'value'          => $value,
				'negate'         => ! empty( $condition['negate'] ),
				'case_sensitive' => ! empty( $condition['case_sensitive'] ),
			);
		}

		return $clean;
	}

	/**
	 * Whether a variable name is one this type can read.
	 *
	 * @param string $variable Variable name.
	 */
	protected function variable_is_known( string $variable ): bool {
		if ( isset( $this->variable_options()[ $variable ] ) ) {
			return true;
		}

		if ( ! $this->variables_are_free_form() ) {
			return false;
		}

		foreach ( $this->variable_prefixes() as $prefix ) {
			if ( 0 === strpos( $variable, $prefix . '.' ) && strlen( $variable ) > strlen( $prefix ) + 1 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Compile the condition list.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<array<string, mixed>>
	 */
	protected function compile_conditions( array $settings ): array {
		$rules = array();

		foreach ( $settings['conditions'] ?? array() as $condition ) {
			if ( is_array( $condition ) ) {
				$rules[] = $this->compile_condition( $condition );
			}
		}

		if ( array() === $rules ) {
			return array();
		}

		/*
		 * The library treats a flat list as "any rule matching is a match", so
		 * OR needs no wrapper. AND requires an explicit group.
		 */
		if ( 'all' === ( $settings['match_type'] ?? 'any' ) && count( $rules ) > 1 ) {
			return array(
				array(
					'type'  => 'AND',
					'rules' => $rules,
				),
			);
		}

		return $rules;
	}

	/**
	 * Compile one condition into the library's structured format.
	 *
	 * @param array<string, mixed> $condition Stored condition.
	 *
	 * @return array<string, mixed>
	 */
	protected function compile_condition( array $condition ): array {
		$operator = (string) ( $condition['operator'] ?? 'equals' );
		$value    = (string) ( $condition['value'] ?? '' );

		$compiled = array(
			'variable'       => (string) ( $condition['variable'] ?? '' ),
			'operator'       => $operator,

			/*
			 * The library gates the structured format on isset() for all three
			 * of variable, operator and value, so an empty string must still be
			 * present for a valueless operator such as `exists`. Omitting it
			 * drops the condition back to the shorthand parser.
			 */
			'value'          => $value,
			'negate'         => ! empty( $condition['negate'] ),
			'case_sensitive' => ! empty( $condition['case_sensitive'] ),
		);

		/*
		 * `in` is a list operator. Splitting it here and declaring the match
		 * mode explicitly avoids the shorthand parser's habit of producing an
		 * array with no match mode set, which compares against nothing.
		 */
		if ( 'in' === $operator ) {
			$compiled['value'] = array_values(
				array_filter(
					array_map( 'trim', explode( ',', $value ) ),
					static fn ( string $item ): bool => '' !== $item
				)
			);

			$compiled['matches'] = 'any';
		}

		return $compiled;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $settings Described by the interface.
	 */
	public function summarize( array $settings ): array {
		$conditions = $settings['conditions'] ?? array();

		if ( array() === $conditions ) {
			return array( __( 'No conditions configured, so this rule matches nothing.', 'basic-firewall' ) );
		}

		$joiner = 'all' === ( $settings['match_type'] ?? 'any' )
			? __( 'all of:', 'basic-firewall' )
			: __( 'any of:', 'basic-firewall' );

		$lines = array( $joiner );

		foreach ( array_slice( $conditions, 0, 5 ) as $condition ) {
			$lines[] = sprintf(
				'%s%s %s %s',
				! empty( $condition['negate'] ) ? 'NOT ' : '',
				(string) ( $condition['variable'] ?? '' ),
				self::OPERATORS[ (string) ( $condition['operator'] ?? 'equals' ) ] ?? '',
				(string) ( $condition['value'] ?? '' )
			);
		}

		if ( count( $conditions ) > 5 ) {
			$lines[] = sprintf(
				/* translators: %d: number of further conditions. */
				__( 'and %d more', 'basic-firewall' ),
				count( $conditions ) - 5
			);
		}

		return $lines;
	}

	/**
	 * {@inheritDoc}
	 *
	 * @param array<string, mixed> $rule Described by the interface.
	 */
	public function compile( array $rule ): array {
		$entry      = $this->base_entry( $rule );
		$conditions = $this->compile_conditions( $rule['settings'] ?? array() );

		if ( array() !== $conditions ) {
			$entry['config'] = $conditions;
		}

		return $entry;
	}
}
