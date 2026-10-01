<?php
/**
 * Shared MaxMind / CDN reader configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

use GeoIp2\Database\Reader;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\Firewall\Utility\GeoHeaderMap;

/**
 * Where a geolocation or ASN rule gets its answer from.
 *
 * Two sources, and the choice is a real trade rather than a preference.
 *
 * **A MaxMind database** is authoritative, works without any proxy
 * configuration, and populates every field. It has to be licensed, downloaded
 * and kept current, and it costs a lookup per request.
 *
 * **The CDN in front of the site** has already resolved the address, so there is
 * nothing to license and no lookup cost. In exchange you are trusting a header,
 * which means trusted proxies must be configured or the library will not believe
 * it -- and only the fields your CDN actually sends are populated, which for
 * most CDNs is a country code and little else. A rule on `city` that worked
 * against a City database stops matching.
 *
 * The reader configuration is kept when the source is switched, so switching
 * back does not lose a database path.
 *
 * There is no license key. One used to be stored here "for whatever downloads
 * the database", and nothing ever read it: the library opens a local file and
 * never downloads one, and its only use for a key is the MaxMind web-service
 * client, which this plugin does not configure. A credential nothing reads is
 * only a liability, so the field went and routine 13 deleted every stored
 * one (#54).
 */
trait Geo_Reader_Settings {

	/**
	 * CDNs whose header names the library knows.
	 *
	 * @return array<string, string>
	 */
	public static function known_edges(): array {
		return array(
			'cloudflare'   => 'Cloudflare',
			'cloudfront'   => 'AWS CloudFront',
			'akamai'       => 'Akamai',
			'fastly'       => 'Fastly',
			'google_cloud' => 'Google Cloud',
			'custom'       => __( 'Something else — map the headers yourself', 'basic-firewall' ),
		);
	}

	/**
	 * Whether this type can read its answer from the CDN at all.
	 *
	 * Geolocation can: the edge resolves the country, and more on request. The
	 * ASN plugin cannot -- it has no header source, and no CDN in the library's
	 * list sends the network -- so offering the choice there would store a
	 * rule that reads nothing.
	 */
	protected function reader_reads_edge(): bool {
		return true;
	}

	/**
	 * How the rule screen presents the reader, field by field.
	 *
	 * Rendered as nested rows named `settings[reader][...]`, so a save posts the
	 * reader back in the shape it was read in. Without this the reader was
	 * never on the page, and saving the rule through the screen threw it away.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	protected function reader_help(): array {
		$source = 'settings[reader][source]';

		$fields = array(
			'source'   => array(
				'label'       => __( 'Where the answer comes from', 'basic-firewall' ),
				'choices'     => array(
					'database' => __( 'A MaxMind database, looked up here', 'basic-firewall' ),
					'edge'     => __( 'The lookup your CDN already did, read from a request header', 'basic-firewall' ),
				),
				'description' => __( '<strong>A geo header is a claim, not a fact.</strong> Anything that can reach the site directly can send <code>CF-IPCountry: US</code> and pick its own country, so the firewall believes these headers only from a trusted proxy — answer the proxy question on the General screen, or this rule matches nothing.', 'basic-firewall' ),
			),
			'database' => array(
				'label'       => __( 'MaxMind database', 'basic-firewall' ),
				'description' => __( 'The path to the <code>.mmdb</code> file. A relative path resolves inside the firewall\'s private directory; an absolute one is used as given. MaxMind databases cannot be redistributed, so the plugin never ships one. A path to a file that is not there yet is saved with a warning — the download job may not have run.', 'basic-firewall' ),
				'show_when'   => $source . ':database',
			),
			'edge'     => array(
				'label'       => __( 'CDN', 'basic-firewall' ),
				'choices'     => self::known_edges(),
				'description' => __( 'Only Cloudflare sends anything without being asked, and only the country. Every other field on every other CDN is opt-in at the edge — a field it did not send matches nothing rather than matching wrongly.', 'basic-firewall' ),
				'show_when'   => $source . ':edge',
			),
			'headers'  => array(
				'label'       => __( 'Header mapping', 'basic-firewall' ),
				'description' => sprintf(
					/* translators: %s: the field names the library accepts. */
					__( 'For a CDN not in the list: one <code>field: Header-Name</code> per line, such as <code>country: X-Geo-Country</code>. The fields are %s.', 'basic-firewall' ),
					'<code>' . implode( '</code>, <code>', array_map( 'esc_html', self::edge_fields() ) ) . '</code>'
				),
				'show_when'   => 'settings[reader][edge]:custom',
			),
		);

		if ( ! $this->reader_reads_edge() ) {
			unset( $fields['source'], $fields['edge'], $fields['headers'], $fields['database']['show_when'] );
		}

		return array(
			'reader' => array(
				'label'  => __( 'Reader', 'basic-firewall' ),
				'fields' => $fields,
			),
		);
	}

	/**
	 * The fields a custom header mapping may name, in the library's vocabulary.
	 *
	 * Read from the library rather than copied: it refuses to start on a field
	 * it does not know, and a firewall that cannot start fails open on every
	 * rule, not only this one.
	 *
	 * @return list<string>
	 */
	public static function edge_fields(): array {
		return GeoHeaderMap::FIELDS;
	}

	/**
	 * Reader defaults.
	 *
	 * @return array<string, mixed>
	 */
	protected function reader_defaults(): array {
		return array(
			'reader' => array(
				'source'   => 'database',
				'database' => '',
				'edge'     => 'cloudflare',
				'headers'  => array(),
			),
		);
	}

	/**
	 * Validate the reader settings.
	 *
	 * @param array<string, mixed>  $settings Raw settings.
	 * @param array<string, string> $errors   Problems, by reference.
	 *
	 * @return array<string, mixed>
	 */
	protected function validate_reader( array $settings, array &$errors ): array {
		$raw    = is_array( $settings['reader'] ?? null ) ? $settings['reader'] : array();
		$source = (string) ( $raw['source'] ?? 'database' );

		/*
		 * A type that cannot read the CDN reads the database, whatever was
		 * stored. The choice is not on its screen, so a stored `edge` could
		 * only have come from somewhere else, and it never worked.
		 */
		if ( ! $this->reader_reads_edge() ) {
			$source = 'database';
		}

		/*
		 * Built from the keys it knows, so a `license_key` an older version
		 * stored, or a document still carries, is not kept (#54).
		 */
		$reader = array(
			'source'   => in_array( $source, array( 'database', 'edge' ), true ) ? $source : 'database',
			// Kept whichever source is chosen, so switching back loses nothing.
			'database' => trim( (string) ( $raw['database'] ?? '' ) ),
			'edge'     => (string) ( $raw['edge'] ?? 'cloudflare' ),
			'headers'  => array(),
		);

		if ( ! isset( self::known_edges()[ $reader['edge'] ] ) ) {
			$reader['edge'] = 'cloudflare';
		}

		/*
		 * Stored as a map, typed as lines. Both arrive here -- the screen posts
		 * lines, and every other writer re-validates what was stored -- so a
		 * map is turned back into the lines it was read from. Reading its
		 * values alone threw the field names away, and a custom mapping lost
		 * itself the next time anything saved the settings.
		 */
		$headers = $raw['headers'] ?? array();

		if ( is_array( $headers ) ) {
			$pairs = array();

			foreach ( $headers as $field => $header ) {
				$pairs[] = is_string( $field ) ? $field . ': ' . (string) $header : (string) $header;
			}

			$headers = $pairs;
		}

		foreach ( self::lines_to_list( $headers ) as $line ) {
			if ( 1 !== preg_match( '/^([A-Za-z0-9_.-]+)\s*:\s*(\S.*)$/', $line, $matches ) ) {
				$errors['reader.headers'] = sprintf(
					/* translators: %s: the rejected line. */
					__( '%s is not a field-to-header mapping. Write one per line, as "country: CF-IPCountry".', 'basic-firewall' ),
					$line
				);

				continue;
			}

			$field = strtolower( $matches[1] );

			/*
			 * Refused rather than stored. The library throws on a field it does
			 * not know when the rule is built, and the firewall fails open on
			 * every rule when that happens -- so a typo here would switch off
			 * the whole firewall, not merely this rule. Its own spelling is
			 * accepted whatever the case: `country.name`, not `country_name`.
			 */
			$known = array_combine( array_map( 'strtolower', self::edge_fields() ), self::edge_fields() );

			if ( ! isset( $known[ $field ] ) ) {
				$errors['reader.headers'] = sprintf(
					/* translators: 1: the rejected field, 2: the fields accepted. */
					__( '%1$s is not a field the firewall can read from a header. Use one of: %2$s.', 'basic-firewall' ),
					$matches[1],
					implode( ', ', self::edge_fields() )
				);

				continue;
			}

			$reader['headers'][ $known[ $field ] ] = trim( $matches[2] );
		}

		if ( 'database' === $reader['source'] && '' === $reader['database'] ) {
			$errors['reader.database'] = __( 'Give the path to the MaxMind database, or read the location from your CDN instead.', 'basic-firewall' );
		}

		if ( 'edge' === $reader['source'] && 'custom' === $reader['edge'] && array() === $reader['headers'] ) {
			$errors['reader.headers'] = __( 'A custom edge needs at least one field-to-header mapping, or the rule reads nothing and matches nothing.', 'basic-firewall' );
		}

		return array( 'reader' => $reader );
	}

	/**
	 * Write the reader configuration into a compiled entry.
	 *
	 * @param array<string, mixed> $entry    Compiled entry so far.
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return array<string, mixed>
	 */
	protected function apply_reader( array $entry, array $settings ): array {
		$reader   = is_array( $settings['reader'] ?? null ) ? $settings['reader'] : array();
		$metadata = $entry['metadata'] ?? array();

		/*
		 * The library's own keys, which this used to miss entirely. It wrote
		 * `source: headers`, `edge` and a top-level `database`; the library
		 * reads `source: header`, `provider` and `reader: {type, db}`. Every
		 * one of those rules compiled, loaded, reported healthy -- and matched
		 * nothing, because the plugin found no reader and no header source.
		 */
		if ( $this->reader_reads_edge() && 'edge' === ( $reader['source'] ?? 'database' ) ) {
			$edge = (string) ( $reader['edge'] ?? 'cloudflare' );

			$metadata['source'] = 'header';

			// Stored under the name this plugin shows; the library calls it gcp.
			$metadata['provider'] = 'google_cloud' === $edge ? 'gcp' : $edge;

			if ( 'custom' === $edge && array() !== ( $reader['headers'] ?? array() ) ) {
				$metadata['headers'] = $reader['headers'];
			}

			$entry['metadata'] = $metadata;

			return $entry;
		}

		$database = trim( (string) ( $reader['database'] ?? '' ) );

		/*
		 * No reader at all when there is no path, rather than a reader naming
		 * nothing: the library treats an absent reader as "not configured" and
		 * skips the rule, and a configured one it cannot open as a failure it
		 * fails closed on.
		 */
		if ( '' !== $database ) {
			$metadata['reader'] = array(
				'type' => 'reader',
				'db'   => Plugin::instance()->paths()->resolve( $database ),
			);
		}

		$entry['metadata'] = $metadata;

		return $entry;
	}

	/**
	 * Anything that would stop the reader working.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 *
	 * @return list<string>
	 */
	protected function reader_requirements( array $settings ): array {
		$reader   = is_array( $settings['reader'] ?? null ) ? $settings['reader'] : array();
		$problems = array();

		if ( $this->reader_reads_edge() && 'edge' === ( $reader['source'] ?? 'database' ) ) {
			/*
			 * The one failure nobody notices. Without trusted proxies the
			 * library will not believe the header, so the rule matches nothing
			 * -- and geo blocking that silently does not work is
			 * indistinguishable from nobody from those countries visiting.
			 */
			if ( 'yes' !== (string) Plugin::instance()->settings()->get( 'global.behind_proxy', 'unknown' ) ) {
				$problems[] = __( 'This rule reads the visitor location from your CDN, but the site has not been told it is behind a proxy. The firewall will not trust the header, so the rule matches nothing and geo blocking silently does not work. Answer the proxy question on the General screen and configure your trusted proxies.', 'basic-firewall' );
			}

			return $problems;
		}

		$database = trim( (string) ( $reader['database'] ?? '' ) );

		if ( '' === $database ) {
			return array( __( 'No MaxMind database is configured, so this rule matches nothing.', 'basic-firewall' ) );
		}

		$resolved = Plugin::instance()->paths()->resolve( $database );

		if ( ! is_readable( $resolved ) ) {
			$problems[] = sprintf(
				/* translators: %s: database path. */
				__( 'The MaxMind database at %s cannot be read, so this rule matches nothing.', 'basic-firewall' ),
				$resolved
			);

			return $problems;
		}

		$mismatch = $this->reader_database_problem( $settings );

		if ( null !== $mismatch ) {
			$problems[] = $mismatch;
		}

		return $problems;
	}

	/**
	 * The GeoIP2 reader method the library's plugin looks a visitor up with.
	 *
	 * The geolocation plugin calls `city()` for every variable, country
	 * included; the ASN plugin calls `asn()`.
	 */
	protected function reader_lookup(): string {
		return 'city';
	}

	/**
	 * What each lookup needs a database's type to contain, and what to use.
	 *
	 * GeoIP2's reader refuses a lookup on a database whose type does not
	 * contain the string it expects -- `city()` on anything without `City` in
	 * its type, `asn()` on anything but `GeoLite2-ASN` -- by throwing, and the
	 * library catches that and resolves the variable to nothing. So a Country
	 * database behind a geolocation rule, or a City one behind an ASN rule,
	 * opened, loaded, reported itself healthy, and matched nobody.
	 *
	 * @return array<string, array{0: string, 1: string}> Lookup to the required
	 *                                                    substring and the
	 *                                                    databases that have it.
	 */
	protected static function reader_database_types(): array {
		return array(
			'city' => array( 'City', 'GeoLite2-City or GeoIP2-City' ),
			'asn'  => array( 'GeoLite2-ASN', 'GeoLite2-ASN' ),
		);
	}

	/**
	 * Why the configured database cannot answer this rule's lookup, or null.
	 *
	 * Reads the database's own metadata -- its `databaseType` -- which is
	 * what the reader decides by. Only a database that exists and is readable
	 * is checked; a missing one is reported by reader_requirements(), and may
	 * be a download that has not run yet.
	 *
	 * Public because the compiler asks it too, so the problem reaches the
	 * Status screen and Site Health rather than only the rule's own screen.
	 *
	 * @param array<string, mixed> $settings Rule settings.
	 */
	public function reader_database_problem( array $settings ): ?string {
		$reader = is_array( $settings['reader'] ?? null ) ? $settings['reader'] : array();

		if ( $this->reader_reads_edge() && 'edge' === ( $reader['source'] ?? 'database' ) ) {
			return null;
		}

		$database = trim( (string) ( $reader['database'] ?? '' ) );

		if ( '' === $database ) {
			return null;
		}

		$resolved = Plugin::instance()->paths()->resolve( $database );

		if ( ! is_file( $resolved ) || ! is_readable( $resolved ) ) {
			return null;
		}

		$wanted = self::reader_database_types()[ $this->reader_lookup() ] ?? null;

		if ( null === $wanted ) {
			return null;
		}

		try {
			$type = ( new Reader( $resolved ) )->metadata()->databaseType;
		} catch ( \Throwable $e ) {
			return sprintf(
				/* translators: 1: database path, 2: the reader's complaint. */
				__( 'The file at %1$s is not a MaxMind database the reader can open, so this rule matches nothing: %2$s', 'basic-firewall' ),
				$resolved,
				$e->getMessage()
			);
		}

		if ( false !== strpos( $type, $wanted[0] ) ) {
			return null;
		}

		return sprintf(
			/* translators: 1: database path, 2: its database type, 3: the databases that would work. */
			__( 'The MaxMind database at %1$s is a %2$s database, which cannot answer this rule\'s lookups: every one fails, so the rule matches nothing. Use a %3$s database.', 'basic-firewall' ),
			$resolved,
			$type,
			$wanted[1]
		);
	}
}
