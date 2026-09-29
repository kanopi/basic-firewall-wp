<?php
/**
 * Adds the site's own names to what the library redacts from its logs.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Logging;

use Kanopi\Firewall\Logging\LoggingFactory;

/**
 * The Logging screen's "additional variables to redact", handed to the library.
 *
 * At debug level the library records the value each condition compared, so a
 * rule reading a header or a cookie writes it into the log. The library
 * redacts a sensible set by default -- the cookie and authorization headers,
 * a few token headers, every cookie -- and a site adds its own names here: a
 * session header of its own, an API key header. The setting was stored and
 * shown and never passed on, so the names typed into it were logged in clear.
 *
 * **Added to the defaults, never in place of them.** The screen asks for
 * *additional* names, and replacing the list would stop redacting the
 * cookie header the moment somebody added one.
 *
 * **Runs without WordPress.** The wp-config.php bootstrap loads this by hand,
 * like Decision_Dispatcher, and passes the names from the runtime sidecar;
 * the runner passes them from settings. So nothing here may call WordPress.
 *
 * Redaction changes what is logged and nothing else: conditions are always
 * evaluated against the real value.
 */
final class Redaction {

	/**
	 * The library's own list, as it was before anything was added to it.
	 *
	 * Captured once, so applying a different set later in the same process --
	 * a test, a long-running worker -- replaces the additions rather than
	 * piling them up.
	 *
	 * @var list<string>|null
	 */
	private static ?array $defaults = null;

	/**
	 * Redact these names as well as the library's own.
	 *
	 * @param array<mixed> $names Variable names, such as `header.x-session`, or a prefix such as `query.*`.
	 */
	public static function apply( array $names ): void {
		if ( null === self::$defaults ) {
			self::$defaults = array_values( LoggingFactory::getRedactedVariables() );
		}

		$extra = self::clean( $names );

		LoggingFactory::setRedactedVariables( array_values( array_unique( array_merge( self::$defaults, $extra ) ) ) );
	}

	/**
	 * The names worth passing on: strings, trimmed, lowercased, once each.
	 *
	 * Lowercased because the library matches case-insensitively by lowering
	 * the variable name, so an entry typed `Header.X-Token` would otherwise
	 * never match anything.
	 *
	 * @param array<mixed> $names What was stored.
	 *
	 * @return list<string>
	 */
	public static function clean( array $names ): array {
		$clean = array();

		foreach ( $names as $name ) {
			$name = is_string( $name ) ? strtolower( trim( $name ) ) : '';

			if ( '' !== $name && ! in_array( $name, $clean, true ) ) {
				$clean[] = $name;
			}
		}

		return $clean;
	}
}
