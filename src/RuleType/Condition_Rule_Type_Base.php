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

	use Has_Sources;

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
			'sources'    => array(),
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

			$variable = $this->join_variable(
				trim( (string) ( $condition['variable'] ?? '' ) ),
				trim( (string) ( $condition['variable_name'] ?? '' ) )
			);
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

			if ( in_array( $variable, $this->variable_prefixes(), true ) ) {
				$errors[ "conditions.$index.variable" ] = sprintf(
					/* translators: %s: the family name, such as query or header. */
					__( '%s needs a name beside it. The family on its own reads nothing — a condition on it would match nothing at all.', 'basic-firewall' ),
					$variable
				);

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
			 * Stored as the pattern body, and checked as the pattern the
			 * library will actually be given -- which is not the same string.
			 * Validating what was typed and running something else is how a
			 * lowercased `\D` went unnoticed.
			 *
			 * A pattern pasted with its own delimiters is unwrapped rather than
			 * refused: somebody who has written regular expressions before will
			 * type them out of habit, and the alternative is a rule that matches
			 * a literal hash.
			 */
			if ( 'regex' === $operator ) {
				$value     = self::regex_body( $value );
				$assembled = self::assemble_regex( $value, ! empty( $condition['case_sensitive'] ) );

				// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( '' === $assembled || false === @preg_match( $assembled, '' ) ) {
					$errors[ "conditions.$index.value" ] = sprintf(
						/* translators: %s: the pattern as the firewall would run it. */
						__( 'That is not a valid regular expression. The firewall would run it as %s. Write the pattern only — the delimiters and the case flag are added for you from the box beside it.', 'basic-firewall' ),
						$assembled
					);

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

		$clean['sources'] = $this->validate_sources( (array) ( $settings['sources'] ?? array() ), $errors );

		/*
		 * The variable a list matches on has to be one this type can actually
		 * read. Checked here rather than left to the library, which would
		 * accept the name, resolve it to nothing, and compare against nothing
		 * on every request -- a rule reporting itself active and matching
		 * nothing, which is the failure this plugin exists to prevent.
		 */
		$variables = $this->variable_options();

		foreach ( $clean['sources'] as $index => $source ) {
			$variable = (string) ( $source['variable'] ?? '' );

			if ( '' === $variable || '' !== (string) ( $source['template'] ?? '' ) ) {
				continue;
			}

			if ( ! isset( $variables[ $variable ] ) && ! $this->is_prefixed_variable( $variable ) ) {
				$errors[ 'sources.' . $index . '.variable' ] = sprintf(
					/* translators: %s: the rejected variable. */
					__( '%s is not something this rule type can read, so every entry in the list would be compared against nothing.', 'basic-firewall' ),
					$variable
				);

				$clean['sources'][ $index ]['variable'] = '';
			}
		}

		return $clean;
	}

	/**
	 * Put a family and a name back together.
	 *
	 * The rule screen asks for `query` and `test` in two columns, because a
	 * family on its own reads nothing and a free-text box for the whole thing
	 * invites `quest`. Storage stays one string: it is what the library reads,
	 * and what every export, import and CLI command already carries.
	 *
	 * A name given for something that is not a family is discarded rather than
	 * appended -- the column is hidden for those, so a value there is a
	 * leftover from a different selection rather than an instruction.
	 *
	 * @param string $variable The chosen variable or family.
	 * @param string $name     The name beside it, if any.
	 */
	protected function join_variable( string $variable, string $name ): string {
		if ( '' === $name || ! in_array( $variable, $this->variable_prefixes(), true ) ) {
			return $variable;
		}

		return $variable . '.' . ltrim( $name, '.' );
	}

	/**
	 * Whether a variable belongs to one of this type's prefixed families.
	 *
	 * `header.user-agent` and `cookie.session` are not in the options list and
	 * are perfectly readable -- the list names the families, and the suffix is
	 * whatever the site happens to send.
	 *
	 * @param string $variable Candidate variable.
	 */
	private function is_prefixed_variable( string $variable ): bool {
		foreach ( $this->variable_prefixes() as $prefix ) {
			if ( 0 === strpos( $variable, $prefix . '.' ) ) {
				return true;
			}
		}

		return false;
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
	 * {@inheritDoc}
	 *
	 * Yes, and this reverses an earlier no.
	 *
	 * The first version of referenced lists supported the IP rule alone, on the
	 * grounds that a source here feeds condition *values* rather than a flat
	 * list and is therefore a different shape. It is a different shape and not
	 * a harder one: the library renders a template per entry, a template may be
	 * a map, and a map is exactly what a condition already compiles to. The
	 * library's own shipped presets do this -- `ai-crawlers` references a list
	 * of agent fragments and templates each into a `header.user-agent` match.
	 */
	public function supports_sources(): bool {
		return true;
	}

	/**
	 * Turn one referenced entry into a condition.
	 *
	 * Built as a structured map rather than the `variable@operator:{value}`
	 * shorthand the library also accepts. The map is the same shape
	 * `compile_condition()` produces for a condition somebody typed, so an
	 * entry from a list and an entry from the form are evaluated by identical
	 * code -- including negation, case sensitivity, and the operator names this
	 * plugin uses, which the shorthand parser spells differently in places.
	 *
	 * @param array<string, mixed> $source The referenced list.
	 *
	 * @return string|array<string, mixed>|null
	 */
	protected function source_template( array $source ) {
		// An explicit template wins: somebody who wrote one meant it.
		$template = trim( (string) ( $source['template'] ?? '' ) );

		if ( '' !== $template ) {
			return $template;
		}

		$variable = trim( (string) ( $source['variable'] ?? '' ) );

		if ( '' === $variable ) {
			return null;
		}

		return $this->compile_condition(
			array(
				'variable'       => $variable,
				'operator'       => (string) ( $source['operator'] ?? 'contains' ),

				/*
				 * The placeholder, not a value. The library substitutes the
				 * record into every leaf string of the template, so this is
				 * where each line of the list lands.
				 */
				'value'          => '{value}',
				'negate'         => ! empty( $source['negate'] ),
				'case_sensitive' => false,
			)
		);
	}

	/**
	 * Delimiters tried, in order, when wrapping a pattern.
	 *
	 * The first one the pattern does not itself contain is used, which avoids
	 * escaping in every ordinary case -- a path pattern gets `#`, and one about
	 * fragments or colours falls through to `~`.
	 */
	private const REGEX_DELIMITERS = array( '#', '~', '%', '!', '@' );

	/**
	 * Wrap a pattern body in delimiters and the flags the condition asked for.
	 *
	 * The stored value is the pattern *body* -- what goes between the
	 * delimiters -- rather than a complete `#...#i`. Three things follow from
	 * that, and they are the reason for it:
	 *
	 * Nobody has to know about delimiters. An undelimited pattern used to be
	 * accepted by the field and rejected by the library, so the rule saved,
	 * reported itself active, and matched nothing.
	 *
	 * The case-sensitivity box works here exactly as it does on every other
	 * operator, instead of being a control that had to be hidden because it did
	 * something harmful.
	 *
	 * And the flags are ours to set, so the pattern the library receives is
	 * always one it can run.
	 *
	 * A body that arrives already delimited is unwrapped first. Somebody who
	 * has written regular expressions before will type `#foo#i` out of habit,
	 * and the alternative is matching a literal hash.
	 *
	 * @param string $body           The pattern body, or a delimited pattern.
	 * @param bool   $case_sensitive Whether case matters.
	 */
	public static function assemble_regex( string $body, bool $case_sensitive ): string {
		$body = self::regex_body( $body );

		if ( '' === $body ) {
			return '';
		}

		$delimiter = self::REGEX_DELIMITERS[0];

		foreach ( self::REGEX_DELIMITERS as $candidate ) {
			if ( false === strpos( $body, $candidate ) ) {
				$delimiter = $candidate;

				break;
			}
		}

		// Every candidate appears in the body, so the chosen one is escaped.
		if ( false !== strpos( $body, $delimiter ) ) {
			$body = str_replace( $delimiter, '\\' . $delimiter, $body );
		}

		return $delimiter . $body . $delimiter . ( $case_sensitive ? '' : 'i' );
	}

	/**
	 * The pattern body, with any delimiters and flags taken back off.
	 *
	 * Accepts what this plugin stores and what somebody used to writing regular
	 * expressions will type anyway. A settings document written before the
	 * change holds delimited patterns, and this is what lets one load.
	 *
	 * @param string $value Stored value.
	 */
	public static function regex_body( string $value ): string {
		$value = trim( $value );

		if ( strlen( $value ) < 2 ) {
			return $value;
		}

		$delimiter = $value[0];

		if ( ! in_array( $delimiter, self::REGEX_DELIMITERS, true ) && '/' !== $delimiter ) {
			return $value;
		}

		$close = strrpos( $value, $delimiter );

		// A single delimiter, or one only at the start, is not a wrapped
		// pattern -- `#tag` is somebody matching a literal hash.
		if ( false === $close || 0 === $close ) {
			return $value;
		}

		$flags = substr( $value, $close + 1 );

		// Anything after the closing delimiter has to look like PCRE flags, or
		// this was never a delimited pattern in the first place.
		if ( '' !== $flags && 1 !== preg_match( '/^[imsxuADSUXJn]+$/', $flags ) ) {
			return $value;
		}

		return substr( $value, 1, $close - 1 );
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

			/*
			 * Always true for a regular expression, and the checkbox is honoured
			 * a different way -- see assemble_regex() below.
			 *
			 * The library implements case-insensitivity by lowercasing both
			 * sides of the comparison before it runs -- and for this operator
			 * one of those sides is the pattern. Lowercasing a pattern does not
			 * make it case-insensitive; it rewrites it, and for the uppercase
			 * metacharacter escapes it rewrites it into its own opposite:
			 *
			 *     \D  non-digit       becomes  \d  digit
			 *     \W  non-word        becomes  \w  word
			 *     \S  non-whitespace  becomes  \s  whitespace
			 *     [A-Z]               becomes  [a-z]
			 *
			 * So `#\D+#` -- written to match anything that is not a number --
			 * matched only numbers, in a rule that saved, validated, and
			 * reported itself active.
			 *
			 * The pattern therefore reaches the library untouched, and the
			 * administrator's choice is carried in the one place a regular
			 * expression expresses it: its own `i` flag.
			 */
			'case_sensitive' => 'regex' === $operator || ! empty( $condition['case_sensitive'] ),
		);

		if ( 'regex' === $operator ) {
			$compiled['value'] = self::assemble_regex( $value, ! empty( $condition['case_sensitive'] ) );
		}

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

		$sources = $this->compile_sources( $rule );

		if ( array() !== $sources ) {
			$entry['metadata']['sources'] = $sources;

			/*
			 * `config` is present even when empty once a list is referenced.
			 * The library appends a source's rendered entries to this plugin's
			 * config list, and a rule whose only conditions come from a list
					 * would otherwise compile without the key at all.
			 */
			if ( ! isset( $entry['config'] ) ) {
				$entry['config'] = array();
			}
		}

		return $entry;
	}
}
