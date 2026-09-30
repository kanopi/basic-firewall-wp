<?php
/**
 * Finds, masks and restores the credentials in the Advanced screen's YAML.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Transfer;

use Symfony\Component\Yaml\Yaml;

/**
 * Credentials typed into the free-form advanced YAML.
 *
 * Everywhere else a credential lives at a path the schema or a rule type
 * declares, so Secret_Paths can find it. The advanced block has no schema: it
 * is whatever the library accepts, typed by hand. So credentials are recognised
 * by the *shape of the key* they sit under, and the rule is deliberately
 * precise, because a false positive here is not harmless -- a value shown as
 * [redacted] is a value nobody can read back on the screen that owns it.
 *
 * **The rule.** Key names are compared case-insensitively, with `-` read as
 * `_`, at any depth:
 *
 * - A name containing `password`, `passwd`, `secret` or `token` is a
 *   credential -- unless it ends in a suffix that makes it a description of a
 *   credential rather than one (`_name`, `_ttl`, `_header`, `_cookie`,
 *   `_param`, `_field`, `_length`, `_file`, `_path`, `_env`, `_type`, and the
 *   like), so `cookie_name` and `token_ttl` stay visible.
 * - These exact names are credentials: `pass`, `pwd`, `auth`, `api_key`,
 *   `apikey`, `access_key`, `private_key`, `secret_key`, `license_key`.
 *   Under `auth` or `credentials`, every scalar is -- except, in an `auth`
 *   map, the `type`, `header` and `username` that describe it.
 * - A bare `key` is **not**. The library uses it for what a rate limit
 *   counts, and `site_key`, `public_key`, `default_key` and `cache_key` are not
 *   secrets either.
 * - Under a `headers` map, a header whose name mentions `auth`, `token`,
 *   `secret`, `cookie`, `password` or `api-key`/`apikey` (`Authorization`,
 *   `X-Api-Key`, `Cookie`) is a credential; `X-Frame-Options` is not.
 * - In any string, wherever it is: the password of `scheme://user:pass@host`
 *   (or the whole user part when there is no colon, which is how a token is
 *   put in a URL), a query parameter named like a credential (`token`,
 *   `api_key`, `key`, `password`, `signature` ...), and a `password=` or `pwd=`
 *   segment of a `;`-separated DSN. Only that part is masked, so the host stays
 *   readable -- which is also why `dsn` is not on the list of names above: a
 *   DSN with no credential in it holds nothing to hide.
 *
 * `%env(NAME)%` and `%file(/path)%` are references rather than values, so
 * they are always shown, whole or inside a URL.
 *
 * **The round trip.** A credential is shown as `[redacted]` (inside a URL,
 * only its password is). Posted back unchanged, at the same path, with the
 * host, port or URL beside it unchanged, the placeholder means "keep the stored
 * value", as a list's advanced block does (#23). A placeholder that has moved,
 * or whose connection changed around it, cannot be restored -- and is refused
 * rather than stored, because a stored `[redacted]` is a credential that
 * silently no longer works.
 */
final class Advanced_Yaml_Secrets {

	/**
	 * What a credential is shown as.
	 */
	public const PLACEHOLDER = Secret_Paths::REDACTED;

	/**
	 * Fragments that make a key a credential wherever they appear in its name.
	 */
	private const NAME_FRAGMENTS = array( 'password', 'passwd', 'secret', 'token' );

	/**
	 * Suffixes that make such a name describe a credential rather than hold one.
	 */
	private const DESCRIPTIVE_SUFFIXES = array( '_name', '_ttl', '_lifetime', '_expires', '_length', '_header', '_cookie', '_param', '_field', '_file', '_path', '_dir', '_env', '_type', '_enabled', '_required', '_source' );

	/**
	 * Names that are credentials exactly as spelled.
	 */
	private const EXACT_NAMES = array( 'pass', 'pwd', 'auth', 'api_key', 'apikey', 'access_key', 'private_key', 'secret_key', 'license_key', 'credentials' );

	/**
	 * Header names, as a pattern, whose value is a credential.
	 */
	private const HEADER_PATTERN = '/auth|token|secret|cookie|password|api[-_]?key/i';

	/**
	 * Query parameter names whose value is a credential.
	 */
	private const QUERY_NAMES = array( 'token', 'access_token', 'auth', 'auth_token', 'api_key', 'apikey', 'key', 'password', 'pass', 'pwd', 'secret', 'client_secret', 'signature', 'sig' );

	/**
	 * Sibling keys a credential belongs with.
	 *
	 * A placeholder is restored only while these are unchanged beside it, so
	 * pointing a connection at another host in the same save does not carry
	 * the stored password there -- the binding an import applies too.
	 */
	private const BOUND_SIBLINGS = array( 'host', 'hostname', 'port', 'url', 'uri', 'endpoint', 'server', 'socket' );

	/**
	 * Every credential in a YAML document, in document order.
	 *
	 * @param string $yaml The advanced YAML.
	 *
	 * @return list<array{path: list<string|int>, value: string|int|float, masked: string}>
	 */
	public static function find( string $yaml ): array {
		$tree = self::parse( $yaml );

		return null === $tree ? array() : self::walk( $tree, array(), '' );
	}

	/**
	 * The dotted path of every credential in a document, for a report.
	 *
	 * @param string $yaml The advanced YAML.
	 *
	 * @return list<string>
	 */
	public static function paths( string $yaml ): array {
		return array_map( static fn ( array $entry ): string => self::dotted( $entry['path'] ), self::find( $yaml ) );
	}

	/**
	 * Every literal credential value, for redacting a document built from this one.
	 *
	 * @param string $yaml The advanced YAML.
	 *
	 * @return list<string>
	 */
	public static function values( string $yaml ): array {
		$values = array();

		foreach ( self::find( $yaml ) as $entry ) {
			$values[] = (string) $entry['value'];
		}

		return array_values( array_unique( $values ) );
	}

	/**
	 * The document with every credential masked, and where they were.
	 *
	 * The text is kept as typed -- comments and layout included -- with only
	 * each credential's scalar replaced. That substitution is checked by
	 * parsing the result: when it does not produce exactly the masked tree (a
	 * block scalar, an anchor shared with another key, a credential repeated in
	 * a comment), the masked tree is dumped instead. Losing the comments is the
	 * price of never putting a credential in the page.
	 *
	 * @param string $yaml The advanced YAML.
	 *
	 * @return array{text: string, redacted: list<string>}
	 */
	public static function mask( string $yaml ): array {
		$tree = self::parse( $yaml );

		if ( null === $tree ) {
			return array(
				'text'     => $yaml,
				'redacted' => array(),
			);
		}

		$entries = self::walk( $tree, array(), '' );

		if ( array() === $entries ) {
			return array(
				'text'     => $yaml,
				'redacted' => array(),
			);
		}

		$masked       = $tree;
		$replacements = array();

		foreach ( $entries as $entry ) {
			self::set( $masked, $entry['path'], $entry['masked'] );

			$replacements[] = array(
				'find'    => (string) $entry['value'],
				'replace' => self::quote( $entry['masked'] ),
			);
		}

		$text   = self::substitute( $yaml, $replacements );
		$values = array_map( static fn ( array $entry ): string => (string) $entry['value'], $entries );

		if ( null === $text || self::parse( $text ) !== $masked || self::contains_any( $text, $values ) ) {
			$text = self::dump( $masked );
		}

		return array(
			'text'     => $text,
			'redacted' => array_map( static fn ( array $entry ): string => self::dotted( $entry['path'] ), $entries ),
		);
	}

	/**
	 * Put the stored credentials back where a posted document has placeholders.
	 *
	 * `ok` is false when a placeholder cannot be matched to a stored value --
	 * `unrestored` names where -- and the text is then the posted text, which
	 * must not be stored. With `$drop`, used by an import, such a placeholder
	 * is removed instead and `ok` stays true.
	 *
	 * @param string $posted The YAML as posted.
	 * @param string $stored The YAML stored before this save.
	 * @param bool   $drop   Remove what cannot be restored, rather than refuse.
	 *
	 * @return array{ok: bool, text: string, unrestored: list<string>}
	 */
	public static function restore( string $posted, string $stored, bool $drop = false ): array {
		$result = array(
			'ok'         => true,
			'text'       => $posted,
			'unrestored' => array(),
		);

		if ( false === strpos( $posted, self::PLACEHOLDER ) ) {
			return $result;
		}

		$tree = self::parse( $posted );

		if ( null === $tree ) {
			// Not ours to report: the caller refuses YAML that does not parse.
			return $result;
		}

		$stored_tree = self::parse( $stored ) ?? array();
		$known       = array();
		$written     = array();
		$entries     = self::walk( $stored_tree, array(), '' );

		foreach ( $entries as $entry ) {
			$known[ self::key( $entry['path'] ) ] = $entry;
		}

		/*
		 * How each stored value was written -- quoted or not, and how -- so
		 * a restored document is the stored one byte for byte rather than an
		 * equivalent with different quoting in the history.
		 */
		$snippets = array();

		self::substitute(
			$stored,
			array_map(
				static fn ( array $entry ): array => array(
					'find'    => (string) $entry['value'],
					'replace' => '',
				),
				$entries
			),
			$snippets
		);

		foreach ( $entries as $index => $entry ) {
			if ( isset( $snippets[ $index ] ) ) {
				$written[ self::key( $entry['path'] ) ] = $snippets[ $index ];
			}
		}

		$restored     = $tree;
		$replacements = array();
		$lost         = array();

		foreach ( self::placeholders( $tree, array() ) as $leaf ) {
			$entry = $known[ self::key( $leaf['path'] ) ] ?? null;

			if ( null === $entry || $entry['masked'] !== $leaf['value'] || ! self::siblings_unchanged( $tree, $stored_tree, $leaf['path'] ) ) {
				$lost[] = $leaf['path'];

				continue;
			}

			self::set( $restored, $leaf['path'], $entry['value'] );

			$replacements[] = array(
				'find'    => $leaf['value'],
				'replace' => $written[ self::key( $leaf['path'] ) ] ?? self::inline( $entry['value'] ),
			);
		}

		if ( array() !== $lost ) {
			$result['unrestored'] = array_map( array( self::class, 'dotted' ), $lost );

			if ( ! $drop ) {
				$result['ok'] = false;

				return $result;
			}

			foreach ( array_reverse( $lost ) as $path ) {
				self::remove( $restored, $path );
			}

			$result['text'] = self::dump( $restored );

			return $result;
		}

		$text = self::substitute( $posted, $replacements );

		$result['text'] = null !== $text && self::parse( $text ) === $restored ? $text : self::dump( $restored );

		return $result;
	}

	/**
	 * Parse a document into a tree, or null when it is empty or not a map.
	 *
	 * @param string $yaml The YAML.
	 *
	 * @return array<mixed>|null
	 */
	private static function parse( string $yaml ): ?array {
		if ( '' === trim( $yaml ) ) {
			return null;
		}

		try {
			$parsed = Yaml::parse( $yaml );
		} catch ( \Throwable $e ) {
			return null;
		}

		return is_array( $parsed ) ? $parsed : null;
	}

	/**
	 * Collect the credentials under a node.
	 *
	 * @param array<mixed>     $node    The node.
	 * @param list<string|int> $path    Its path.
	 * @param string           $context What the node is: '', `auth`, `all` or `headers`.
	 *
	 * @return list<array{path: list<string|int>, value: string|int|float, masked: string}>
	 */
	private static function walk( array $node, array $path, string $context ): array {
		$found = array();

		foreach ( $node as $key => $child ) {
			$here = array_merge( $path, array( $key ) );
			$name = is_string( $key ) ? str_replace( '-', '_', strtolower( $key ) ) : '';

			// A placeholder, quoted or not, is not a credential: it is where one was.
			if ( self::PLACEHOLDER === $child || array( 'redacted' ) === $child ) {
				continue;
			}

			if ( is_array( $child ) ) {
				$found = array_merge( $found, self::walk( $child, $here, self::child_context( $name, $context ) ) );

				continue;
			}

			if ( ! self::is_value( $child ) ) {
				continue;
			}

			if ( self::is_credential( $name, is_string( $key ) ? $key : '', $context ) ) {
				if ( ! Secret_Paths::is_token( $child ) ) {
					$found[] = array(
						'path'   => $here,
						'value'  => $child,
						'masked' => self::PLACEHOLDER,
					);
				}

				continue;
			}

			if ( is_string( $child ) ) {
				$masked = self::mask_string( $child );

				if ( $masked !== $child ) {
					$found[] = array(
						'path'   => $here,
						'value'  => $child,
						'masked' => $masked,
					);
				}
			}
		}

		return $found;
	}

	/**
	 * What the children of a key are, for the rule.
	 *
	 * @param string $name    The key, normalised.
	 * @param string $context The key's own context.
	 */
	private static function child_context( string $name, string $context ): string {
		if ( 'all' === $context || 'credentials' === $name ) {
			return 'all';
		}

		if ( 'auth' === $name ) {
			return 'auth';
		}

		if ( 'headers' === $name ) {
			return 'headers';
		}

		/*
		 * A key named like a credential that holds a list -- `auth: [user, pass]`
		 * for Redis ACL, `password: [...]` -- is credentials all the way down.
		 */
		if ( self::named_like_credential( $name ) && 'auth' !== $name ) {
			return 'all';
		}

		return '';
	}

	/**
	 * Whether a scalar at this key is a credential.
	 *
	 * @param string $name    The key, normalised.
	 * @param string $raw     The key as written.
	 * @param string $context What the enclosing node is.
	 */
	private static function is_credential( string $name, string $raw, string $context ): bool {
		switch ( $context ) {
			case 'all':
				return true;

			case 'auth':
				// A list under `auth` is the ACL pair; a map describes itself.
				return '' === $name || ! in_array( $name, array( 'type', 'header', 'username', 'user' ), true );

			case 'headers':
				if ( 1 === preg_match( self::HEADER_PATTERN, $raw ) ) {
					return true;
				}
				break;
		}

		return self::named_like_credential( $name );
	}

	/**
	 * Whether a key's name alone makes its value a credential.
	 *
	 * @param string $name The key, normalised.
	 */
	private static function named_like_credential( string $name ): bool {
		if ( '' === $name ) {
			return false;
		}

		if ( in_array( $name, self::EXACT_NAMES, true ) ) {
			return true;
		}

		foreach ( self::DESCRIPTIVE_SUFFIXES as $suffix ) {
			if ( str_ends_with( $name, $suffix ) ) {
				return false;
			}
		}

		foreach ( self::NAME_FRAGMENTS as $fragment ) {
			if ( str_contains( $name, $fragment ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Whether a scalar can hold a credential: a non-empty string or a number.
	 *
	 * @param mixed $value The scalar.
	 */
	private static function is_value( $value ): bool {
		if ( is_string( $value ) ) {
			return '' !== trim( $value );
		}

		return is_int( $value ) || is_float( $value );
	}

	/**
	 * A string with the credential parts inside it masked.
	 *
	 * @param string $value The string.
	 */
	private static function mask_string( string $value ): string {
		if ( Secret_Paths::is_token( $value ) ) {
			return $value;
		}

		// scheme://user:pass@ -- the password; scheme://token@ -- the user part.
		$value = (string) preg_replace_callback(
			'#^([a-z][a-z0-9+.\-]*://)([^/@\s:?\#]*)(?::([^/@\s?\#]*))?@#i',
			static function ( array $m ): string {
				$has_pass = isset( $m[3] );
				$secret   = $has_pass ? $m[3] : $m[2];

				if ( '' === $secret || self::references( $secret ) ) {
					return $m[0];
				}

				return $has_pass
					? $m[1] . $m[2] . ':' . self::PLACEHOLDER . '@'
					: $m[1] . self::PLACEHOLDER . '@';
			},
			$value
		);

		// A credential in the query string, such as token or api_key.
		$value = (string) preg_replace_callback(
			'#([?&])([^=&\#\s]+)=([^&\#\s]*)#',
			static function ( array $m ): string {
				$name = str_replace( '-', '_', strtolower( urldecode( $m[2] ) ) );

				if ( '' === $m[3] || ! in_array( $name, self::QUERY_NAMES, true ) || self::references( $m[3] ) ) {
					return $m[0];
				}

				return $m[1] . $m[2] . '=' . self::PLACEHOLDER;
			},
			$value
		);

		// mysql:host=...;password=... -- a PDO-style DSN.
		return (string) preg_replace_callback(
			'#(^|;)(\s*(?:password|pwd)\s*=)([^;]*)#i',
			static function ( array $m ): string {
				if ( '' === trim( $m[3] ) || self::references( $m[3] ) ) {
					return $m[0];
				}

				return $m[1] . $m[2] . self::PLACEHOLDER;
			},
			$value
		);
	}

	/**
	 * Whether part of a string is, or holds, a reference rather than a value.
	 *
	 * @param string $part The part.
	 */
	private static function references( string $part ): bool {
		return str_contains( $part, '%env(' ) || str_contains( $part, '%file(' ) || self::PLACEHOLDER === $part;
	}

	/**
	 * Every placeholder in a posted tree, in document order.
	 *
	 * `[redacted]` typed without quotes is a YAML list holding `redacted`, so
	 * that spelling is recognised as the placeholder too.
	 *
	 * @param array<mixed>     $node The node.
	 * @param list<string|int> $path Its path.
	 *
	 * @return list<array{path: list<string|int>, value: string}>
	 */
	private static function placeholders( array $node, array $path ): array {
		$found = array();

		foreach ( $node as $key => $child ) {
			$here = array_merge( $path, array( $key ) );

			if ( array( 'redacted' ) === $child ) {
				$found[] = array(
					'path'  => $here,
					'value' => self::PLACEHOLDER,
				);

				continue;
			}

			if ( is_array( $child ) ) {
				$found = array_merge( $found, self::placeholders( $child, $here ) );

				continue;
			}

			if ( is_string( $child ) && str_contains( $child, self::PLACEHOLDER ) ) {
				$found[] = array(
					'path'  => $here,
					'value' => $child,
				);
			}
		}

		return $found;
	}

	/**
	 * Whether the host, port and URL beside a credential are what they were.
	 *
	 * @param array<mixed>     $posted The posted tree.
	 * @param array<mixed>     $stored The stored tree.
	 * @param list<string|int> $path   The credential's path.
	 */
	private static function siblings_unchanged( array $posted, array $stored, array $path ): bool {
		// Walk up to the nearest map: a credential in an ACL list belongs with the map holding the list.
		do {
			array_pop( $path );

			$posted_parent = self::get( $posted, $path );
			$stored_parent = self::get( $stored, $path );
		} while ( array() !== $path && is_array( $posted_parent ) && array_is_list( $posted_parent ) );

		if ( ! is_array( $posted_parent ) || ! is_array( $stored_parent ) ) {
			return true;
		}

		foreach ( $posted_parent as $key => $value ) {
			if ( is_string( $key ) && in_array( strtolower( $key ), self::BOUND_SIBLINGS, true ) && ! array_key_exists( $key, $stored_parent ) ) {
				return false;
			}
		}

		foreach ( $stored_parent as $key => $value ) {
			if ( ! is_string( $key ) || ! in_array( strtolower( $key ), self::BOUND_SIBLINGS, true ) ) {
				continue;
			}

			$now = $posted_parent[ $key ] ?? null;

			// A URL shown masked compares by its masked form.
			if ( is_string( $value ) && is_string( $now ) && self::mask_string( $value ) === $now ) {
				continue;
			}

			// Loosely, because a port arrives as "6379" as often as 6379.
			if ( ! is_scalar( $value ) || ! is_scalar( $now ) || (string) $value !== (string) $now ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Replace scalars in YAML text, in order, leaving the rest as typed.
	 *
	 * Each value is looked for from where the last replacement ended, as a
	 * whole scalar: single-quoted, double-quoted or plain, following a `:`,
	 * `-`, `[`, `,` or `{` and ending the line or the flow item. Null when one
	 * cannot be found; the caller then falls back to dumping the tree.
	 *
	 * @param string                                     $yaml         The text.
	 * @param list<array{find: string, replace: string}> $replacements What to replace, in document order.
	 * @param array<int, string>                         $matched      What each replaced, as written, by reference.
	 */
	private static function substitute( string $yaml, array $replacements, array &$matched = array() ): ?string {
		$cursor  = 0;
		$matched = array();

		foreach ( $replacements as $index => $replacement ) {
			$find    = $replacement['find'];
			$pattern = '/(?<=[\s:\[,{\-])(?:'
				. preg_quote( "'" . str_replace( "'", "''", $find ) . "'", '/' )
				. '|' . preg_quote( '"' . addcslashes( $find, '"\\' ) . '"', '/' )
				. '|' . preg_quote( $find, '/' )
				. ')(?=[ \t]*(?:#.*)?$|[ \t]*[,\]}])/m';

			if ( 1 !== preg_match( $pattern, $yaml, $match, PREG_OFFSET_CAPTURE, $cursor ) ) {
				return null;
			}

			$offset            = (int) $match[0][1];
			$matched[ $index ] = (string) $match[0][0];
			$yaml              = substr( $yaml, 0, $offset ) . $replacement['replace'] . substr( $yaml, $offset + strlen( (string) $match[0][0] ) );
			$cursor            = $offset + strlen( $replacement['replace'] );
		}

		return $yaml;
	}

	/**
	 * Whether any credential still appears in the text, comments included.
	 *
	 * @param string       $text   The text.
	 * @param list<string> $values The credentials.
	 */
	private static function contains_any( string $text, array $values ): bool {
		foreach ( $values as $value ) {
			if ( '' !== $value && str_contains( $text, $value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * A string as a single-quoted YAML scalar.
	 *
	 * @param string $value The string.
	 */
	private static function quote( string $value ): string {
		return "'" . str_replace( "'", "''", $value ) . "'";
	}

	/**
	 * A stored scalar as inline YAML.
	 *
	 * @param string|int|float $value The value.
	 */
	private static function inline( $value ): string {
		return Yaml::dump( $value );
	}

	/**
	 * A tree as YAML text.
	 *
	 * @param array<mixed> $tree The tree.
	 */
	private static function dump( array $tree ): string {
		return Yaml::dump( $tree, 12, 2, Yaml::DUMP_MULTI_LINE_LITERAL_BLOCK );
	}

	/**
	 * A path as dots, for a person.
	 *
	 * @param list<string|int> $path The path.
	 */
	public static function dotted( array $path ): string {
		return implode( '.', array_map( 'strval', $path ) );
	}

	/**
	 * A path as an unambiguous array key.
	 *
	 * @param list<string|int> $path The path.
	 */
	private static function key( array $path ): string {
		return implode( "\0", array_map( static fn ( $segment ): string => ( is_int( $segment ) ? 'i' : 's' ) . $segment, $path ) );
	}

	/**
	 * Read a node at a path.
	 *
	 * @param array<mixed>     $tree The tree.
	 * @param list<string|int> $path The path.
	 *
	 * @return mixed
	 */
	private static function get( array $tree, array $path ) {
		$node = $tree;

		foreach ( $path as $segment ) {
			if ( ! is_array( $node ) || ! array_key_exists( $segment, $node ) ) {
				return null;
			}

			$node = $node[ $segment ];
		}

		return $node;
	}

	/**
	 * Write a value at a path that exists.
	 *
	 * @param array<mixed>     $tree  The tree, by reference.
	 * @param list<string|int> $path  The path.
	 * @param mixed            $value The value.
	 */
	private static function set( array &$tree, array $path, $value ): void {
		$cursor = &$tree;

		foreach ( $path as $segment ) {
			if ( ! is_array( $cursor ) ) {
				$cursor = array();
			}

			$cursor = &$cursor[ $segment ];
		}

		$cursor = $value;

		unset( $cursor );
	}

	/**
	 * Remove the value at a path.
	 *
	 * @param array<mixed>     $tree The tree, by reference.
	 * @param list<string|int> $path The path.
	 */
	private static function remove( array &$tree, array $path ): void {
		$last   = array_pop( $path );
		$cursor = &$tree;

		foreach ( $path as $segment ) {
			if ( ! is_array( $cursor ) || ! array_key_exists( $segment, $cursor ) ) {
				return;
			}

			$cursor = &$cursor[ $segment ];
		}

		if ( is_array( $cursor ) ) {
			$was_list = array_is_list( $cursor );

			unset( $cursor[ $last ] );

			if ( $was_list ) {
				$cursor = array_values( $cursor );
			}
		}

		unset( $cursor );
	}
}
