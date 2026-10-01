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
	 * Settings a rule type refused while merging.
	 *
	 * @var list<array{path: string, message: string}>
	 */
	private array $problems = array();

	/**
	 * Settings the document carried that this version no longer stores, and why.
	 *
	 * @var list<string>
	 */
	private array $dropped = array();

	/**
	 * Stored credentials an import did not carry across, and why.
	 *
	 * @var list<string>
	 */
	private array $withheld = array();

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

		$this->dropped = array();

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
		$this->problems = array();

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

		/*
		 * Settings a rule type refused are reported alongside the schema's own
		 * complaints rather than swallowed. An import that quietly dropped half
		 * a rule's configuration and said "imported" would be the worst of both
		 * -- the document says one thing, the site enforces another, and
		 * nothing connects them.
		 */
		return array(
			'ok'       => true,
			'error'    => null,
			'summary'  => $preview['summary'],
			'problems' => array_merge( $this->problems, $problems ),
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
		$result = $this->preserve_credentials( $current, $result, $incoming );

		return $this->restore_advanced_yaml( $current, $result, $incoming );
	}

	/**
	 * Put this site's credentials back into an imported advanced YAML.
	 *
	 * An export shows each credential in the advanced block as [redacted].
	 * Where this site's own block has the same credential at the same place,
	 * with the same host beside it, it is kept -- the round trip an export
	 * then import of one site makes. Anywhere else the key is dropped, never
	 * stored as the placeholder, and the preview says so; the block is then
	 * re-written from its parsed form, so its comments do not survive.
	 *
	 * @param array<string, mixed> $current  Current settings.
	 * @param array<string, mixed> $result   Merged settings.
	 * @param array<string, mixed> $incoming What the document says.
	 *
	 * @return array<string, mixed>
	 */
	private function restore_advanced_yaml( array $current, array $result, array $incoming ): array {
		if ( ! is_string( $incoming['advanced_yaml'] ?? null ) ) {
			return $result;
		}

		$restored = Advanced_Yaml_Secrets::restore( $incoming['advanced_yaml'], (string) ( $current['advanced_yaml'] ?? '' ), true );

		$result['advanced_yaml'] = $restored['text'];

		foreach ( $restored['unrestored'] as $path ) {
			$this->withheld[] = sprintf(
				/* translators: %s: the credential's path inside the advanced YAML. */
				__( 'advanced_yaml: %s was exported as [redacted], and this site\'s Advanced YAML has no matching credential to keep, so the key is left out. Add it on the Advanced screen, ideally as a %%env(NAME)%% token.', 'basic-firewall' ),
				$path
			);
		}

		return $result;
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

			$rule = $this->drop_retired_settings( $rule );

			/*
			 * An incoming rule is merged over the site's existing rule of the
			 * same id, not substituted for it -- which is what carries a local
			 * API key through an import of a document that had it stripped.
			 */
			$by_id[ $id ] = isset( $existing_by_id[ $id ] )
				? $this->merge_section( $existing_by_id[ $id ], $rule )
				: $rule;

			$by_id[ $id ] = $this->normalise_settings( $by_id[ $id ] );
		}

		return array_values( $by_id );
	}

	/**
	 * Take out of an incoming rule a setting this version no longer has, and say so.
	 *
	 * The geolocation and ASN license key (#54): stored for years, read by
	 * nothing, and removed along with every stored copy. A document exported
	 * before that still carries it -- usually empty, since exports strip
	 * credentials, but a hand-written one may hold a real key. The import
	 * goes ahead without it rather than failing over a value that would
	 * never have been used, and the preview names each rule it came out of
	 * so the key is not believed to have been kept.
	 *
	 * @param array<string, mixed> $rule One incoming rule.
	 *
	 * @return array<string, mixed>
	 */
	private function drop_retired_settings( array $rule ): array {
		if ( ! in_array( (string) ( $rule['type'] ?? '' ), array( 'geolocation', 'asn' ), true ) ) {
			return $rule;
		}

		if ( ! is_array( $rule['settings']['reader'] ?? null ) || ! array_key_exists( 'license_key', $rule['settings']['reader'] ) ) {
			return $rule;
		}

		unset( $rule['settings']['reader']['license_key'] );

		$this->dropped[] = sprintf(
			/* translators: %s: the rule identifier. */
			__( 'rules.%s.settings.reader.license_key: the MaxMind license key is no longer stored. Nothing ever read it -- the firewall opens the database file and never downloads one -- so the rule is imported without it.', 'basic-firewall' ),
			(string) ( $rule['id'] ?? '' )
		);

		return $rule;
	}

	/**
	 * Put an incoming rule's settings through its own type's validator.
	 *
	 * Until this existed, the rule form was the only thing that ever called
	 * `validate_settings()`, so a document could write any shape it liked
	 * straight into the settings option. The shapes are not interchangeable: a
	 * rate limit path is `"/wp-login.php 20 60"` as typed and a map of pattern,
	 * limit and window once validated, and a type handed the wrong one threw
	 * where it was read -- which was the rules listing, so importing a document
	 * could leave the screen you would use to find the bad rule unable to load.
	 *
	 * Also the place a hostile document is defanged. Everything else about an
	 * import is checked; this was the one field that went in verbatim.
	 *
	 * A type that rejects part of what arrives keeps the rest, because refusing
	 * the whole rule would silently drop something the document plainly asked
	 * for. What is dropped is reported like any other import problem.
	 *
	 * @param array<string, mixed> $rule One incoming rule.
	 *
	 * @return array<string, mixed>
	 */
	private function normalise_settings( array $rule ): array {
		$type = Plugin::instance()->rule_types()->get( (string) ( $rule['type'] ?? '' ) );

		if ( null === $type ) {
			return $rule;
		}

		$errors = array();

		try {
			$rule['settings'] = $type->validate_settings( (array) ( $rule['settings'] ?? array() ), $errors );
		} catch ( \Throwable $e ) {
			$this->problems[] = array(
				'path'    => sprintf( 'rules.%s.settings', (string) ( $rule['id'] ?? '' ) ),
				'message' => sprintf(
					/* translators: %s: error message. */
					__( 'These settings could not be read and were left as they arrived: %s', 'basic-firewall' ),
					$e->getMessage()
				),
			);

			return $rule;
		}

		foreach ( $errors as $field => $message ) {
			$this->problems[] = array(
				'path'    => sprintf( 'rules.%s.settings.%s', (string) ( $rule['id'] ?? '' ), (string) $field ),
				'message' => (string) $message,
			);
		}

		return $rule;
	}

	/**
	 * Put back any credential the incoming document did not carry.
	 *
	 * The whole point of the importer. An absent or empty credential means the
	 * document did not carry it, so the receiving site keeps what it has --
	 * **but only while it still goes where it went.** A document that points
	 * Redis at another host, a database connection at another server or a
	 * list at another URL, with the password stripped, would otherwise have
	 * this site's credential sent to wherever the document names. So each
	 * credential is kept only while every setting it is bound to is unchanged
	 * (Secret_Paths::bindings_in()); otherwise it is blanked, and the preview
	 * says so. That applies as well to a credential the merge itself carried
	 * over from the stored section or rule, which is how a stripped Redis
	 * password used to follow a new host in.
	 *
	 * Rules are matched by identifier, not by position: the rules in the
	 * result are not necessarily in the order they were stored in.
	 *
	 * A URL exported with its credential replaced by `***` is restored from the
	 * stored copy when the two match apart from the credential -- which also
	 * means the same host.
	 *
	 * @param array<string, mixed> $current  Current settings.
	 * @param array<string, mixed> $result   Merged settings.
	 * @param array<string, mixed> $incoming What the document says.
	 *
	 * @return array<string, mixed>
	 */
	private function preserve_credentials( array $current, array $result, array $incoming = array() ): array {
		$this->withheld = array();

		foreach ( Secret_Paths::bindings_in( $current ) as $path => $bound ) {
			$existing = Secret_Paths::get( $current, $path );

			if ( Secret_Paths::is_empty( $existing ) ) {
				// Nothing to preserve.
				continue;
			}

			$target = self::translate( $path, $current, $result );

			if ( null === $target ) {
				// The rule it belonged to is gone.
				continue;
			}

			$now = Secret_Paths::get( $result, $target );

			if ( ! Secret_Paths::is_empty( $now ) && $now !== $existing ) {
				// The document carries a credential of its own.
				continue;
			}

			$moved = array();

			foreach ( $bound as $anchor ) {
				$anchor_target = self::translate( $anchor, $current, $result );

				if ( ! self::same_setting( Secret_Paths::get( $current, $anchor ), null === $anchor_target ? null : Secret_Paths::get( $result, $anchor_target ) ) ) {
					$moved[] = null === $anchor_target ? $anchor : $anchor_target;
				}
			}

			if ( array() === $moved ) {
				Secret_Paths::set( $result, $target, $existing );

				continue;
			}

			// Carried by the document itself, the same value: it asked for it.
			if ( self::incoming_value( $target, $result, $incoming ) === $existing ) {
				continue;
			}

			Secret_Paths::set( $result, $target, is_array( $existing ) ? array() : '' );

			$this->withheld[] = sprintf(
				/* translators: 1: the credential's path, 2: the settings that changed. */
				__( '%1$s is not kept, because %2$s changed and it would be sent somewhere new.', 'basic-firewall' ),
				$target,
				implode( ', ', $moved )
			);
		}

		foreach ( Secret_Paths::urls_in( $current ) as $path ) {
			$existing = Secret_Paths::get( $current, $path );
			$target   = self::translate( $path, $current, $result );

			if ( ! is_string( $existing ) || null === $target ) {
				continue;
			}

			$clean = Secret_Paths::redact_url( $existing );

			if ( $clean !== $existing && Secret_Paths::get( $result, $target ) === $clean ) {
				Secret_Paths::set( $result, $target, $existing );
			}
		}

		// A URL still carrying the export's placeholder has nothing to restore it from.
		foreach ( Secret_Paths::urls_in( $result ) as $path ) {
			$value = Secret_Paths::get( $result, $path );

			if ( is_string( $value ) && false !== strpos( $value, '***' ) && Secret_Paths::redact_url( $value ) === $value ) {
				$this->withheld[] = sprintf(
					/* translators: %s: the URL's path in the document. */
					__( '%s still has *** where the exporting site removed a credential, and this site has no copy of that URL to take it from. Put the credential back by hand.', 'basic-firewall' ),
					$path
				);
			}
		}

		return $result;
	}

	/**
	 * Whether a setting a credential is bound to is unchanged.
	 *
	 * Loosely for scalars, because a port arrives as `"6379"` from YAML typed by
	 * hand and as `6379` once validated; and a URL counts as unchanged when it
	 * differs only by the credential the export replaced.
	 *
	 * @param mixed $was What the site has.
	 * @param mixed $now What the import would leave.
	 */
	private static function same_setting( $was, $now ): bool {
		if ( $was === $now ) {
			return true;
		}

		if ( ( null === $was || is_scalar( $was ) ) && ( null === $now || is_scalar( $now ) ) && (string) $was === (string) $now ) {
			return true;
		}

		return is_string( $was ) && is_string( $now ) && Secret_Paths::redact_url( $was ) === Secret_Paths::redact_url( $now );
	}

	/**
	 * Where a path in the stored settings is in the merged result.
	 *
	 * The same for everything but a rule, which is found by its identifier.
	 *
	 * @param string               $path    A path in the stored settings.
	 * @param array<string, mixed> $current Current settings.
	 * @param array<string, mixed> $result  Merged settings.
	 *
	 * @return string|null Null when the rule is not in the result.
	 */
	private static function translate( string $path, array $current, array $result ): ?string {
		if ( 1 !== preg_match( '/^rules\.([^.]+)(\..*)?$/', $path, $matches ) ) {
			return $path;
		}

		$id = (string) ( $current['rules'][ $matches[1] ]['id'] ?? '' );

		if ( '' === $id ) {
			return null;
		}

		foreach ( (array) ( $result['rules'] ?? array() ) as $index => $rule ) {
			if ( is_array( $rule ) && (string) ( $rule['id'] ?? '' ) === $id ) {
				return 'rules.' . $index . ( $matches[2] ?? '' );
			}
		}

		return null;
	}

	/**
	 * What the document itself said at a path of the merged result.
	 *
	 * @param string               $path     A path in the merged result.
	 * @param array<string, mixed> $result   Merged settings.
	 * @param array<string, mixed> $incoming What the document says.
	 *
	 * @return mixed
	 */
	private static function incoming_value( string $path, array $result, array $incoming ) {
		if ( 1 !== preg_match( '/^rules\.([^.]+)\.(.+)$/', $path, $matches ) ) {
			return Secret_Paths::get( $incoming, $path );
		}

		$id = (string) ( $result['rules'][ $matches[1] ]['id'] ?? '' );

		foreach ( (array) ( $incoming['rules'] ?? array() ) as $rule ) {
			if ( is_array( $rule ) && '' !== $id && (string) ( $rule['id'] ?? '' ) === $id ) {
				return Secret_Paths::get( $rule, $matches[2] );
			}
		}

		return null;
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
			'mode'                 => $mode,
			'rules_new'            => array_values( array_diff( $incoming_ids, $current_ids ) ),
			'rules_overwritten'    => array_values( array_intersect( $incoming_ids, $current_ids ) ),
			'rules_removed'        => array_values( array_diff( $current_ids, $result_ids ) ),
			'sections_changed'     => $sections,
			'credentials_withheld' => $this->withheld,
			'settings_dropped'     => $this->dropped,

			/*
			 * Credentials the document's advanced YAML carries in the clear.
			 * Kept -- the document asked for them -- but named, so importing a
			 * block with a password typed into it is not a silent act.
			 */
			'advanced_credentials' => is_string( $incoming['advanced_yaml'] ?? null ) ? Advanced_Yaml_Secrets::paths( $incoming['advanced_yaml'] ) : array(),
		);
	}
}
