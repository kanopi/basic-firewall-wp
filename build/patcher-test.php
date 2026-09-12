<?php
/**
 * Proves the scoper patcher is correct and idempotent.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

/*
 * Run as part of the build, before scoping, because a patcher that double-applies
 * the prefix produces a class name that resolves to nothing -- in a file the
 * library reads at runtime, in a build that otherwise looks like it worked.
 */

// Define the Finder the config file imports, so it can be loaded standalone.
if ( ! class_exists( 'Isolated\\Symfony\\Component\\Finder\\Finder' ) ) {
	eval( 'namespace Isolated\\Symfony\\Component\\Finder; class Finder { public static function create() { return new self(); } public function __call( $n, $a ) { return $this; } }' );
}

require_once __DIR__ . '/../scoper.inc.php';

$prefix   = 'Kanopi\\BasicFirewall\\Vendor';
$failures = array();

/**
 * Assert a condition.
 *
 * @param bool   $condition What must be true.
 * @param string $message   What it means.
 *
 * @return void
 */
function bfw_assert( bool $condition, string $message ): void {
	global $failures;

	if ( $condition ) {
		printf( "  ok    %s\n", $message );

		return;
	}

	printf( "  FAIL  %s\n", $message );

	$failures[] = $message;
}

$input = "logger:\n"
	. "  - class: \"\\\\Monolog\\\\Handler\\\\StreamHandler\"\n"
	. "    args:\n"
	. "      - \"Monolog\\\\Level::INFO\"\n"
	. "plugins:\n"
	. "  - plugin: Kanopi\\Firewall\\Plugins\\Url\n"
	. "  - plugin: \"Kanopi\\\\Firewall\\\\Plugins\\\\IpAddress\"\n";

$once  = basic_firewall_scope_data_file( '/vendor/kanopi/firewall/presets/preset.yml', $prefix, $input );
$twice = basic_firewall_scope_data_file( '/vendor/kanopi/firewall/presets/preset.yml', $prefix, $once );

echo "Patcher output:\n" . $once . "\n";

bfw_assert( $once === $twice, 'the patcher is idempotent' );

bfw_assert(
	false === strpos( $once, 'Vendor\\Kanopi\\BasicFirewall' )
	&& false === strpos( $once, 'Vendor\\\\Kanopi\\\\BasicFirewall' ),
	'the prefix is never applied twice'
);

bfw_assert(
	false !== strpos( $once, 'Kanopi\\BasicFirewall\\Vendor\\Kanopi\\Firewall\\Plugins\\Url' ),
	'a bare reference is prefixed'
);

bfw_assert(
	false !== strpos( $once, 'Kanopi\\\\BasicFirewall\\\\Vendor\\\\Kanopi\\\\Firewall\\\\Plugins\\\\IpAddress' ),
	'an escaped reference is prefixed, keeping its escaping'
);

bfw_assert(
	false !== strpos( $once, 'Kanopi\\\\BasicFirewall\\\\Vendor\\\\Monolog\\\\Handler\\\\StreamHandler' ),
	'a leading-separator reference is prefixed'
);

bfw_assert(
	'plain text' === basic_firewall_scope_data_file( '/vendor/kanopi/firewall/presets/notes.txt', $prefix, 'plain text' ),
	'a file type the library never reads is left alone'
);

/*
 * Composer metadata must be left completely alone. Touching it stripped the
 * prefix PHP-Scoper had written for psr/log, which dropped every Psr\Log class
 * out of the authoritative classmap.
 */
$installed = '{"packages":[{"name":"psr/log","autoload":{"psr-4":{"Kanopi\\\\BasicFirewall\\\\Vendor\\\\Psr\\\\Log\\\\":"src"}}}]}';

bfw_assert(
	$installed === basic_firewall_scope_data_file( '/vendor/composer/installed.json', $prefix, $installed ),
	"Composer's installed.json is left untouched"
);

/*
 * The case that actually shipped broken. PHP-Scoper patches YAML itself and
 * writes the prefix with single backslashes into a double-quoted scalar that
 * escapes them, producing a name no YAML parser resolves correctly. The patcher
 * has to repair that, not add to it.
 */
$scoper_mangled = "logger:\n  - class: \"\\\\Kanopi\\BasicFirewall\\Vendor\\\\Monolog\\\\Handler\\\\StreamHandler\"\n";
$repaired       = basic_firewall_scope_data_file( '/vendor/kanopi/firewall/presets/preset.yml', $prefix, $scoper_mangled );

bfw_assert(
	false === strpos( $repaired, 'Vendor\\\\Kanopi\\BasicFirewall' )
	&& 1 === substr_count( $repaired, 'BasicFirewall' ),
	"PHP-Scoper's own mis-escaped prefix is repaired rather than doubled"
);

bfw_assert(
	$repaired === basic_firewall_scope_data_file( '/vendor/kanopi/firewall/presets/preset.yml', $prefix, $repaired ),
	'repairing is idempotent too'
);

if ( array() === $failures ) {
	echo "\npatcher-test: OK\n";
	exit( 0 );
}

fwrite( STDERR, sprintf( "\npatcher-test: FAILED (%d)\n", count( $failures ) ) );
exit( 1 );
