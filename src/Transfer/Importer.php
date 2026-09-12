<?php
/**
 * Reads a portable configuration document back in.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Transfer;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Validator;
use Symfony\Component\Yaml\Yaml;

/**
 * Imports a document, previewing before it applies anything.
 *
 * **The rule that matters: an empty credential means "not carried", never "set
 * to nothing".** This is the direction that can do real damage. Writing a
 * stripped export over a receiving site would erase that site's challenge
 * secret -- and a firewall that cannot start fails open, so every rule silently
 * stops being enforced. The site would report itself as blocking and would not
 * be.
 *
 * So an import preserves what the receiving site already has, matching rules by
 * identifier rather than by position. An administrator who genuinely wants to
 * clear a credential does it on the screen that owns it, where the consequence
 * is in front of them.
 */
final class Importer {

	/**
	 * Parse a document without applying it.
	 *
	 * @param string $yaml Raw document.
	 *
	 * @return array{ok: bool, error: string|null, settings: array<string, mixed>}
	 */
	public function parse( string $yaml ): array {
		try {
			$parsed = Yaml::parse( $yaml );
		} catch ( \Throwable $e ) {
			return array(
				'ok'       => false,
				'error'    => sprintf(
					/* translators: %s: parser error message. */
					__( 'The document could not be parsed: %s', 'basic-firewall' ),
					$e->getMessage()
				),
				'settings' => array(),
			);
		}

		if ( ! is_array( $parsed ) ) {
			return array(
				'ok'       => false,
				'error'    => __( 'The document is empty or is not a configuration export.', 'basic-firewall' ),
				'settings' => array(),
			);
		}

		// Accept both the wrapped export format and a bare settings document,
		// because the second is what somebody hand-writes.
		$settings = $parsed['basic_firewall']['settings'] ?? $parsed;

		if ( ! is_array( $settings ) ) {
			return array(
				'ok'       => false,
				'error'    => __( 'The document does not contain a settings section.', 'basic-firewall' ),
				'settings' => array(),
			);
		}

		return array(
			'ok'       => true,
			'error'    => null,
			'settings' => $settings,
		);
	}

	/**
	 * Work out what an import would do, without doing it.
	 *
	 * @param string $yaml Raw document.
	 * @param string $mode Either `merge` or `replace`.
	 *
	 * @return array{ok: bool, error: string|null, result: array<string, mixed>, summary: array<string, mixed>}
	 */
	public function preview( string $yaml, string $mode = 'merge' ): array {
		$parsed = $this->parse( $yaml );

		if ( ! $parsed['ok'] ) {
			return array(
				'ok'      => false,
				'error'   => $parsed['error'],
				'result'  => array(),
				'summary' => array(),
			);
		}

		$current  = Plugin::instance()->settings()->all();
		$incoming = $parsed['settings'];

		$result = $this->apply_to( $current, $incoming, $mode );

		return array(
			'ok'      => true,
			'error'   => null,
			'result'  => $result,
			'summary' => $this->summarize( $current, $incoming, $result, $mode ),
		);
	}

	/**
	 * Import a document.
	 *
	 * @param string $yaml Raw document.
	 * @param string $mode Either `merge` or `replace`.
	 *
	 * @return array{ok: bool, error: string|null, summary: array<string, mixed>, problems: list<array{path: string, message: string}>}
	 */
	public function import( string $yaml, string $mode = 'merge' ): array {
		$preview = $this->preview( $yaml, $mode );

		if ( ! $preview['ok'] ) {
			return array(
				'ok'       => false,
				'error'    => $preview['error'],
				'summary'  => array(),
				'problems' => array(),
			);
		}

		$problems = Plugin::instance()->settings()->replace( $preview['result'] );

		return array(
			'ok'       => true,
			'error'    => null,
			'summary'  => $preview['summary'],
			'problems' => $problems,
		);
	}

	/**
	 * Build the document an import would produce.
	 *
	 * @param array<string, mixed> $current  What the site has now.
	 * @param array<string, mixed> $incoming What the document says.
	 * @param string               $mode     Either `merge` or `replace`.
	 *
	 * @return array<string, mixed>
	 */
	private function apply_to( array $current, array $incoming, string $mode ): array {
		if ( 'replace' === $mode ) {
			/*
			 * Replace still starts from the current document rather than from
			 * the schema defaults. "Replace" governs the rule set and the
			 * sections the document carries -- it does not mean "reset
			 * everything the document did not mention", which would silently
			 * revert storage, logging and the challenge configuration to
			 * defaults on a site that only meant to swap its rules.
			 */
			$result = $current;

			if ( isset( $incoming['rules'] ) && is_array( $incoming['rules'] ) ) {
				$result['rules'] = array();
			}
		} else {
			$result = $current;
		}

		foreach ( $incoming as $key => $value ) {
			if ( 'rules' === $key ) {
				continue;
			}

			$result[ $key ] = is_array( $value ) && isset( $result[ $key ] ) && is_array( $result[ $key ] )
				? $this->merge_section( $result[ $key ], $value )
				: $value;
		}

		if ( isset( $incoming['rules'] ) && is_array( $incoming['rules'] ) ) {
			$result['rules'] = $this->merge_rules(
				'replace' === $mode ? array() : (array) ( $current['rules'] ?? array() ),
				$incoming['rules'],
				(array) ( $current['rules'] ?? array() )
			);
		}

		// Restore anything the document did not carry a credential for.
		return $this->preserve_credentials( $current, $result );
	}

	/**
	 * Merge one section, preferring the incoming values.
	 *
	 * @param array<string, mixed> $current  Current section.
	 * @param array<string, mixed> $incoming Incoming section.
	 *
	 * @return array<string, mixed>
	 */
	private function merge_section( array $current, array $incoming ): array {
		foreach ( $incoming as $key => $value ) {
			if ( is_array( $value ) && isset( $current[ $key ] ) && is_array( $current[ $key ] ) && ! array_is_list( $value ) ) {
				$current[ $key ] = $this->merge_section( $current[ $key ], $value );

				continue;
			}

			$current[ $key ] = $value;
		}

		return $current;
	}

	/**
	 * Merge rules, matching by identifier.
	 *
	 * By identifier rather than by position: a document listing three rules and
	 * a site holding five must not overwrite the first three by index and leave
	 * two orphans with somebody else's configuration.
	 *
	 * @param array<int, mixed> $base     Rules to start from.
	 * @param array<int, mixed> $incoming Rules from the document.
	 * @param array<int, mixed> $existing Every rule the site currently has.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function merge_rules( array $base, array $incoming, array $existing ): array {
		$by_id = array();

		foreach ( $base as $rule ) {
			if ( is_array( $rule ) && '' !== (string) ( $rule['id'] ?? '' ) ) {
				$by_id[ (string) $rule['id'] ] = $rule;
			}
		}

		$existing_by_id = array();

		foreach ( $existing as $rule ) {
			if ( is_array( $rule ) && '' !== (string) ( $rule['id'] ?? '' ) ) {
				$existing_by_id[ (string) $rule['id'] ] = $rule;
			}
		}

		foreach ( $incoming as $rule ) {
			if ( ! is_array( $rule ) ) {
				continue;
			}

			$id = (string) ( $rule['id'] ?? '' );

			if ( '' === $id ) {
				continue;
			}

			/*
			 * An incoming rule is merged over the site's existing rule of the
			 * same id, not substituted for it -- which is what carries a local
			 * API key through an import of a document that had it stripped.
			 */
			$by_id[ $id ] = isset( $existing_by_id[ $id ] )
				? $this->merge_section( $existing_by_id[ $id ], $rule )
				: $rule;
		}

		return array_values( $by_id );
	}

	/**
	 * Put back any credential the incoming document did not carry.
	 *
	 * The whole point of the importer. An absent or empty credential means the
	 * document did not carry it, so the receiving site keeps what it has.
	 *
	 * @param array<string, mixed> $current Current settings.
	 * @param array<string, mixed> $result  Merged settings.
	 *
	 * @return array<string, mixed>
	 */
	private function preserve_credentials( array $current, array $result ): array {
		foreach ( Secret_Paths::in( $current ) as $path ) {
			$existing = Secret_Paths::get( $current, $path );

			if ( null === $existing || '' === $existing ) {
				// Nothing to preserve.
				continue;
			}

			$incoming = Secret_Paths::get( $result, $path );

			if ( null === $incoming || '' === $incoming || ( is_string( $incoming ) && '' === trim( $incoming ) ) ) {
				Secret_Paths::set( $result, $path, $existing );
			}
		}

		return $result;
	}

	/**
	 * Describe what an import would change.
	 *
	 * @param array<string, mixed> $current  Current settings.
	 * @param array<string, mixed> $incoming Incoming settings.
	 * @param array<string, mixed> $result   What the import would produce.
	 * @param string               $mode     Import mode.
	 *
	 * @return array<string, mixed>
	 */
	private function summarize( array $current, array $incoming, array $result, string $mode ): array {
		$current_ids = array();

		foreach ( (array) ( $current['rules'] ?? array() ) as $rule ) {
			if ( is_array( $rule ) ) {
				$current_ids[] = (string) ( $rule['id'] ?? '' );
			}
		}

		$incoming_ids = array();

		foreach ( (array) ( $incoming['rules'] ?? array() ) as $rule ) {
			if ( is_array( $rule ) ) {
				$incoming_ids[] = (string) ( $rule['id'] ?? '' );
			}
		}

		$result_ids = array();

		foreach ( (array) ( $result['rules'] ?? array() ) as $rule ) {
			if ( is_array( $rule ) ) {
				$result_ids[] = (string) ( $rule['id'] ?? '' );
			}
		}

		$sections = array();

		foreach ( $incoming as $key => $value ) {
			if ( 'rules' === $key ) {
				continue;
			}

			if ( ( $current[ $key ] ?? null ) !== $value ) {
				$sections[] = (string) $key;
			}
		}

		return array(
			'mode'              => $mode,
			'rules_new'         => array_values( array_diff( $incoming_ids, $current_ids ) ),
			'rules_overwritten' => array_values( array_intersect( $incoming_ids, $current_ids ) ),
			'rules_removed'     => array_values( array_diff( $current_ids, $result_ids ) ),
			'sections_changed'  => $sections,
		);
	}
}
