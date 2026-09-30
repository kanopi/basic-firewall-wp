<?php
/**
 * Plugin Name: Basic Firewall e2e decision recorder
 * Description: Test fixture for HttpEvaluationTest. Records basic_firewall_decision for requests that ask it to. Installed and removed by the test; never shipped.
 *
 * @package Kanopi\BasicFirewall
 */

/*
 * An mu-plugin, because that is what the README tells a listener to be: a
 * refusal ends the request before regular plugins load, and is announced at
 * shutdown to whatever had loaded by then. Its file name sorts before the
 * firewall's loader, so it is listening before anything is evaluated.
 *
 * Only a request carrying `X-Bfw-E2E-Decisions: <token>` is recorded, one
 * JSON line per event into wp-content/bfw-e2e-decisions-<token>.jsonl, so
 * nothing else the site serves meanwhile is written down. The first line
 * says the request reached WordPress at all, and whether the wp-config.php
 * path had already evaluated it.
 */

// phpcs:disable WordPress.Security.ValidatedSanitizedInput, WordPress.WP.AlternativeFunctions -- a test fixture: the header is matched against a strict pattern, and the log is a local file.

$basic_firewall_e2e_token = (string) ( $_SERVER['HTTP_X_BFW_E2E_DECISIONS'] ?? '' );

if ( 1 === preg_match( '/^[a-f0-9]{16}$/', $basic_firewall_e2e_token ) ) {
	$basic_firewall_e2e_write = static function ( array $entry ) use ( $basic_firewall_e2e_token ): void {
		file_put_contents( WP_CONTENT_DIR . '/bfw-e2e-decisions-' . $basic_firewall_e2e_token . '.jsonl', wp_json_encode( $entry ) . "\n", FILE_APPEND | LOCK_EX );
	};

	$basic_firewall_e2e_write(
		array(
			'seen'  => true,
			'early' => ! empty( $GLOBALS['basic_firewall_early']['evaluated'] ),
		)
	);

	add_action(
		'basic_firewall_decision',
		static function ( $event, $type ) use ( $basic_firewall_e2e_write ): void {
			$basic_firewall_e2e_write(
				array(
					'type'     => (string) $type,
					'enforced' => method_exists( $event, 'isEnforced' ) ? (bool) $event->isEnforced() : null,
					'path'     => method_exists( $event, 'getRequest' ) ? (string) $event->getRequest()->getPathInfo() : null,
					'when'     => did_action( 'plugins_loaded' ) ? 'plugins_loaded' : 'shutdown',
				)
			);
		},
		10,
		2
	);
}
