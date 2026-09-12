<?php
/**
 * Shared MaxMind / CDN reader configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

use Kanopi\BasicFirewall\Plugin;

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
 * back does not lose a database path or a license key.
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
	 * Reader defaults.
	 *
	 * @return array<string, mixed>
	 */
	protected function reader_defaults(): array {
		return array(
			'reader' => array(
				'source'      => 'database',
				'database'    => '',
				'license_key' => '',
				'edge'        => 'cloudflare',
				'headers'     => array(),
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

		$reader = array(
			'source'      => in_array( $source, array( 'database', 'edge' ), true ) ? $source : 'database',
			// Kept whichever source is chosen, so switching back loses nothing.
			'database'    => trim( (string) ( $raw['database'] ?? '' ) ),
			'license_key' => trim( (string) ( $raw['license_key'] ?? '' ) ),
			'edge'        => (string) ( $raw['edge'] ?? 'cloudflare' ),
			'headers'     => array(),
		);

		if ( ! isset( self::known_edges()[ $reader['edge'] ] ) ) {
			$reader['edge'] = 'cloudflare';
		}

		foreach ( self::lines_to_list( $raw['headers'] ?? array() ) as $line ) {
			if ( 1 !== preg_match( '/^([A-Za-z0-9_.-]+)\s*:\s*(\S.*)$/', $line, $matches ) ) {
				$errors['reader.headers'] = sprintf(
					/* translators: %s: the rejected line. */
					__( '%s is not a field-to-header mapping. Write one per line, as "country: CF-IPCountry".', 'basic-firewall' ),
					$line
				);

				continue;
			}

			$reader['headers'][ strtolower( $matches[1] ) ] = trim( $matches[2] );
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

		if ( 'edge' === ( $reader['source'] ?? 'database' ) ) {
			$metadata['source'] = 'headers';
			$metadata['edge']   = (string) ( $reader['edge'] ?? 'cloudflare' );

			if ( 'custom' === $metadata['edge'] && array() !== ( $reader['headers'] ?? array() ) ) {
				$metadata['headers'] = $reader['headers'];
			}

			$entry['metadata'] = $metadata;

			return $entry;
		}

		$database = trim( (string) ( $reader['database'] ?? '' ) );

		if ( '' !== $database ) {
			$metadata['database'] = Plugin::instance()->paths()->resolve( $database );
		}

		$license = trim( (string) ( $reader['license_key'] ?? '' ) );

		if ( '' !== $license ) {
			$metadata['license_key'] = $license;
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

		if ( 'edge' === ( $reader['source'] ?? 'database' ) ) {
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
		}

		return $problems;
	}
}
