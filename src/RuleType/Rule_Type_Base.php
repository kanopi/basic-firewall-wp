<?php
/**
 * Shared behaviour for rule types.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

/**
 * The parts of a rule type that are the same for every type.
 */
abstract class Rule_Type_Base implements Rule_Type {

	/**
	 * {@inheritDoc}
	 */
	public function weight(): int {
		return 0;
	}

	/**
	 * {@inheritDoc}
	 */
	public function allowed_responses(): array {
		return array( 'allow', 'challenge', 'block' );
	}

	/**
	 * {@inheritDoc}
	 */
	public function supports_shared_status_code(): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	public function supports_shared_expiration(): bool {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
	public function supports_sources(): bool {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public function default_settings(): array {
		return array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function summarize( array $settings ): array {
		return array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function check_requirements( array $settings ): array {
		if ( ! $this->is_available() ) {
			return array(
				sprintf(
					/* translators: %s: rule type name. */
					__( 'The installed firewall library does not provide the %s rule type. Rules of this type are skipped when the configuration is compiled.', 'basic-firewall' ),
					$this->label()
				),
			);
		}

		return array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function secret_settings(): array {
		return array();
	}

	/**
	 * {@inheritDoc}
	 */
	public function is_available(): bool {
		return class_exists( $this->library_class() );
	}

	/**
	 * The parts of a compiled entry every type shares.
	 *
	 * @param array<string, mixed> $rule The whole rule.
	 *
	 * @return array<string, mixed>
	 */
	protected function base_entry( array $rule ): array {
		$entry = array(
			'plugin'   => $this->library_class(),
			'response' => (string) ( $rule['response'] ?? 'block' ),
			'weight'   => (int) ( $rule['weight'] ?? 0 ),
			'enable'   => true,
		);

		$metadata = array();

		/*
		 * The rule's own identifier, so a log line can say which rule fired.
		 * Without it the library falls back to a name hardcoded per plugin
		 * class -- four IP rules all log as "IP Address" -- and no log query can
		 * tell them apart. The identifier rather than the label, because it is
		 * stable across a rename and unique by construction.
		 */
		$name = trim( (string) ( $rule['id'] ?? '' ) );

		if ( '' !== $name ) {
			$metadata['name'] = $name;
		}

		/*
		 * Zero is written out rather than omitted, which looks like noise and is
		 * not.
		 *
		 * The library reads `metadata['status_code'] ?? 400`, so an absent key
		 * does not mean "unset" -- it means 400. And the blocking response only
		 * falls through to the site-wide `global.banning_status_code` when it
		 * receives an explicit zero. Omitting the key therefore withholds the
		 * site-wide code that both the rule screen and the General screen
		 * promise, and every rule left at its default rejects with 400 Bad
		 * Request instead of the configured 403.
		 *
		 * Only for the types that share it: a type reading a status code out of
		 * its own configuration never consults this metadata, so writing a zero
		 * there would advertise a value the plugin ignores.
		 */
		if ( $this->supports_shared_status_code() ) {
			$metadata['status_code'] = (int) ( $rule['status_code'] ?? 0 );
		}

		$expiration = (int) ( $rule['expiration'] ?? 0 );

		if ( $this->supports_shared_expiration() && $expiration > 0 ) {
			$metadata['default_expiration_time'] = $expiration;
		}

		/*
		 * Only on a challenge. The library reads this key whatever the response
		 * is and ignores it elsewhere, but writing it onto a block or allow
		 * entry would put a value in an exported document that nothing acts on
		 * -- the sort of thing the next reader has to go and disprove.
		 */
		$provider = trim( (string) ( $rule['challenge_provider'] ?? '' ) );

		if ( '' !== $provider && 'challenge' === ( $rule['response'] ?? '' ) ) {
			$metadata['challenge_provider'] = $provider;
		}

		if ( array() !== $metadata ) {
			$entry['metadata'] = $metadata;
		}

		return $entry;
	}

	/**
	 * Split a textarea into a list of trimmed, non-empty lines.
	 *
	 * @param mixed $value Raw textarea value, or an already-split list.
	 *
	 * @return list<string>
	 */
	protected static function lines_to_list( $value ): array {
		if ( is_array( $value ) ) {
			$lines = $value;
		} else {
			$lines = preg_split( '/\R/', (string) $value ) ?: array();
		}

		$out = array();

		foreach ( $lines as $line ) {
			$line = trim( (string) $line );

			if ( '' !== $line ) {
				$out[] = $line;
			}
		}

		return array_values( array_unique( $out ) );
	}

	/**
	 * Join a list back into textarea content.
	 *
	 * @param mixed $value List of lines.
	 */
	protected static function list_to_lines( $value ): string {
		return is_array( $value ) ? implode( "\n", array_map( 'strval', $value ) ) : (string) $value;
	}

	/**
	 * Whether a string is a delimited regular expression.
	 *
	 * The library silently rejects an undelimited pattern, so a rule written as
	 * `^/wp-admin` appears to save and then matches nothing at all. Every screen
	 * that accepts a pattern validates with this rather than hoping.
	 *
	 * @param string $pattern Candidate pattern.
	 */
	protected static function is_delimited_regex( string $pattern ): bool {
		if ( strlen( $pattern ) < 2 ) {
			return false;
		}

		$delimiter = $pattern[0];

		if ( ctype_alnum( $delimiter ) || '\\' === $delimiter || ctype_space( $delimiter ) ) {
			return false;
		}

		$closing = match ( $delimiter ) {
			'(' => ')',
			'[' => ']',
			'{' => '}',
			'<' => '>',
			default => $delimiter,
		};

		$end = strrpos( $pattern, $closing );

		return false !== $end && $end > 0;
	}
}
