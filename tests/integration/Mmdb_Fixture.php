<?php
/**
 * Writes a minimal MaxMind database for tests.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

/**
 * An empty, valid `.mmdb` file with the database type a test asks for.
 *
 * The vendored geoip2 and maxmind-db packages ship no test databases, and a
 * real one cannot be committed -- MaxMind's licence forbids redistribution,
 * which is why the plugin never ships one either. What a type check needs is
 * the metadata, and that is small enough to write: a search tree of one node
 * whose both branches mean "no record", the separator, and the metadata map in
 * the MaxMind DB binary format. The real readers open it -- the pure PHP one
 * and the C extension alike -- and report its type exactly as they would a
 * database downloaded from MaxMind.
 *
 * @see https://maxmind.github.io/MaxMind-DB/
 */
final class Mmdb_Fixture {

	/**
	 * Write a database of a type.
	 *
	 * @param string $path          Where to write it.
	 * @param string $database_type Such as GeoLite2-City or GeoLite2-Country.
	 */
	public static function write( string $path, string $database_type ): void {
		// One node, 24-bit records, both pointing at node_count: "not found".
		$tree = "\x00\x00\x01\x00\x00\x01";

		$metadata = self::map(
			array(
				'binary_format_major_version' => self::uint( 5, 2 ),
				'binary_format_minor_version' => self::uint( 5, 0 ),
				'build_epoch'                 => self::uint( 9, 1700000000 ),
				'database_type'               => self::string( $database_type ),
				'description'                 => self::map( array( 'en' => self::string( 'Basic Firewall test fixture' ) ) ),
				'ip_version'                  => self::uint( 5, 6 ),
				'languages'                   => self::array_of( array( self::string( 'en' ) ) ),
				'node_count'                  => self::uint( 6, 1 ),
				'record_size'                 => self::uint( 5, 24 ),
			)
		);

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- a test fixture in a scratch directory.
		file_put_contents( $path, $tree . str_repeat( "\x00", 16 ) . "\xAB\xCD\xEFMaxMind.com" . $metadata );
	}

	/**
	 * A control byte, with the extended-type byte where the type needs one.
	 *
	 * @param int $type Data type number.
	 * @param int $size Payload size.
	 */
	private static function control( int $type, int $size ): string {
		$extended = $type > 7;
		$first    = ( $extended ? 0 : $type ) << 5;

		if ( $size < 29 ) {
			$head = chr( $first | $size );
			$tail = '';
		} else {
			$head = chr( $first | 29 );
			$tail = chr( $size - 29 );
		}

		return $head . ( $extended ? chr( $type - 7 ) : '' ) . $tail;
	}

	/**
	 * A UTF-8 string, type 2.
	 *
	 * @param string $value The string.
	 */
	private static function string( string $value ): string {
		return self::control( 2, strlen( $value ) ) . $value;
	}

	/**
	 * An unsigned integer: type 5 (16-bit), 6 (32-bit) or 9 (64-bit).
	 *
	 * @param int $type  Data type number.
	 * @param int $value The integer.
	 */
	private static function uint( int $type, int $value ): string {
		$bytes = ltrim( pack( 'J', $value ), "\x00" );

		return self::control( $type, strlen( $bytes ) ) . $bytes;
	}

	/**
	 * A map, type 7, of already-encoded values keyed by string.
	 *
	 * @param array<string, string> $values Encoded values.
	 */
	private static function map( array $values ): string {
		$encoded = self::control( 7, count( $values ) );

		foreach ( $values as $key => $value ) {
			$encoded .= self::string( (string) $key ) . $value;
		}

		return $encoded;
	}

	/**
	 * An array, type 11, of already-encoded values.
	 *
	 * @param list<string> $values Encoded values.
	 */
	private static function array_of( array $values ): string {
		return self::control( 11, count( $values ) ) . implode( '', $values );
	}
}
