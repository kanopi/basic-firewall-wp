<?php
/**
 * The settings schema, expressed in PHP.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Support;

/**
 * Describes the shape of the settings option.
 *
 * This is the translation of the module's `config/schema/*.yml`. Drupal gets
 * typed configuration for free; WordPress hands you an untyped array out of
 * `get_option()` and wishes you luck. Dropping the schema along with the YAML
 * would mean a rule set whose types drift with whatever last wrote them, and
 * a compiler downstream that has to re-guess the type of every value it reads.
 *
 * So the strictness is kept and only the format changes. Every node declares:
 *
 * - `type`     one of bool, int, float, string, text, map, list
 * - `default`  the value used when the key is absent
 * - `choices`  the closed set a string may take, where there is one
 * - `min`/`max` bounds for a number
 * - `secret`   whether the value is a credential, which is what the export
 *              redactor reads to decide what to strip. Declaring it here rather
 *              than in the exporter means a new field is redacted because of
 *              what it is, not because somebody remembered to list it.
 *
 * Rule settings are deliberately absent: a rule's `settings` sub-tree is
 * resolved by its own rule type, so a type contributed through the
 * `basic_firewall_rule_types` filter validates its own configuration exactly as
 * a shipped one does.
 */
final class Schema {

	/**
	 * The option name. One option, one document, mirroring one config object.
	 */
	public const OPTION = 'basic_firewall_settings';

	/**
	 * The option holding the installed schema version, for upgrade routines.
	 */
	public const VERSION_OPTION = 'basic_firewall_schema_version';

	/**
	 * Current schema version. Bumped whenever an upgrade routine is added.
	 */
	public const VERSION = 1;

	/**
	 * The full settings tree.
	 *
	 * @return array<string, mixed>
	 */
	public static function definition(): array {
		return array(
			'type'     => 'map',
			'children' => array(
				'enabled'       => array(
					'type'    => 'bool',
					'label'   => 'Enable the firewall',
					'default' => true,
				),
				'global'        => self::global_section(),
				'storage'       => self::storage_section(),
				'challenge'     => self::challenge_section(),
				'logging'       => self::logging_section(),
				'logger'        => array(
					'type'    => 'list',
					'label'   => 'Log handlers',
					'default' => array(),
					'of'      => self::log_handler(),
				),
				'sources'       => array(
					'type'     => 'map',
					'label'    => 'Imported rule list settings',
					'children' => array(
						'cron_interval' => array(
							'type'    => 'int',
							'label'   => 'Seconds between checking whether a list is due a refresh, 0 to never refresh',
							'default' => 86400,
							'min'     => 0,
						),
					),
				),
				'rules'         => array(
					'type'    => 'list',
					'label'   => 'Firewall rules',
					'default' => array(),
					'of'      => self::rule(),
				),
				'presets'       => array(
					'type'    => 'list',
					'label'   => 'Enabled library presets',
					'default' => array(),
					'of'      => array(
						'type'    => 'string',
						'label'   => 'Preset filename',
						'default' => '',
					),
				),
				'advanced_yaml' => array(
					'type'    => 'text',
					'label'   => 'Additional raw YAML merged over the compiled configuration',
					'default' => '',
				),
			),
		);
	}

	/**
	 * Global settings.
	 *
	 * @return array<string, mixed>
	 */
	private static function global_section(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Global settings',
			'children' => array(
				'bypass_roles'           => array(
					'type'    => 'list',
					'label'   => 'Roles exempt from evaluation',
					/*
					 * Empty by design. A bypass is a hole in the firewall, so it
					 * exists only because somebody asked for it -- while this is
					 * empty the request path is byte-for-byte what it was before
					 * the feature existed.
					 */
					'default' => array(),
					'of'      => array(
						'type'    => 'string',
						'default' => '',
					),
				),
				'mode'                   => array(
					'type'    => 'string',
					'label'   => 'Operating mode',
					/*
					 * Ships in log mode. A firewall can lock an administrator out
					 * of their own site, so nothing is blocked until somebody
					 * deliberately switches this to "block".
					 */
					'default' => 'log',
					'choices' => array( 'block', 'log', 'exception', 'disabled' ),
				),
				'banning_status_code'    => array(
					'type'    => 'int',
					'label'   => 'HTTP status code returned to blocked clients',
					'default' => 403,
					'min'     => 100,
					'max'     => 599,
				),
				'banning_message'        => array(
					'type'    => 'string',
					'label'   => 'Message returned to blocked clients',
					'default' => 'Request blocked. Reference: {{request.id}}',
				),
				'repeat_offender_status' => array(
					'type'    => 'int',
					'label'   => 'HTTP status code returned to already-blocked clients',
					'default' => 403,
					'min'     => 100,
					'max'     => 599,
				),
				'add_to_expire'          => array(
					'type'    => 'int',
					'label'   => 'Seconds added to a block each time an already-blocked client returns',
					'default' => 3600,
					'min'     => 0,
				),
				'behind_proxy'           => array(
					'type'    => 'string',
					'label'   => 'Whether a proxy sits in front of this deployment',
					/*
					 * A string, not a boolean, and the default is "unknown".
					 *
					 * The library distinguishes three states and "never said" is
					 * one of them. A boolean cannot hold the difference between
					 * "asserted no proxy" and "nobody has answered", and those
					 * mean opposite things: the first silences a real security
					 * warning, the second keeps asking. Defaulting to a silent
					 * "no" would answer an open security question on the
					 * administrator's behalf, in the direction that hides it.
					 */
					'default' => 'unknown',
					'choices' => array( 'unknown', 'no', 'yes' ),
				),
				'require_trusted_proxies' => array(
					'type'    => 'bool',
					'label'   => 'Refuse to start unless trusted proxies are configured',
					'default' => false,
				),
				'require_config'         => array(
					'type'    => 'bool',
					'label'   => 'Treat a configuration that fails to load as a startup failure',
					/*
					 * On by default. The library loads configuration leniently: a
					 * malformed file contributes nothing and it starts with
					 * whatever else parsed. Because this plugin compiles
					 * everything into one file, "whatever else parsed" is an empty
					 * ruleset that allows every request and looks exactly like a
					 * working firewall. Traffic is treated the same either way;
					 * this decides whether anyone finds out.
					 */
					'default' => true,
				),
				'blocking_escalation'    => array(
					'type'    => 'list',
					'label'   => 'Blocking escalation stages',
					'default' => array(),
					'of'      => array(
						'type'     => 'map',
						'label'    => 'Escalation stage',
						'children' => array(
							'window'             => array(
								'type'    => 'int',
								'label'   => 'Look-back window in seconds',
								'default' => 3600,
								'min'     => 1,
							),
							'offense'            => array(
								'type'    => 'int',
								'label'   => 'Offenses required within the window',
								'default' => 3,
								'min'     => 1,
							),
							'duration'           => array(
								'type'    => 'int',
								'label'   => 'Block duration in seconds, 0 for permanent',
								'default' => 86400,
								'min'     => 0,
							),
							'use_plugin_default' => array(
								'type'    => 'bool',
								'label'   => 'Use the matching rule default duration instead of the duration above',
								'default' => false,
							),
						),
					),
				),
			),
		);
	}

	/**
	 * Blocked-client storage.
	 *
	 * @return array<string, mixed>
	 */
	private static function storage_section(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Blocked client storage',
			'children' => array(
				'backend'  => array(
					'type'    => 'string',
					'label'   => 'Storage backend',
					/*
					 * File by default, database recommended in the readme rather
					 * than set here. File is faster on a quiet site (0.007 ms
					 * against 0.07 ms) and needs no credentials, which also makes
					 * it the only backend that works on the early wp-config.php
					 * path. It loses once the block list passes roughly a hundred
					 * clients, which an attack reaches in seconds. Flipping the
					 * default would make the common small site pay for the rare
					 * large one, so the readme explains the trade instead.
					 */
					'default' => 'file',
					'choices' => array( 'memory', 'file', 'database' ),
				),
				'file'     => array(
					'type'     => 'map',
					'label'    => 'File storage settings',
					'children' => array(
						'storage_file' => array(
							'type'    => 'string',
							'label'   => 'Blocked client file',
							'default' => 'private://blocked.data',
						),
						'offense_file' => array(
							'type'    => 'string',
							'label'   => 'Offense history file',
							'default' => 'private://offenses.data',
						),
					),
				),
				'database' => array(
					'type'     => 'map',
					'label'    => 'Database storage settings',
					'children' => array(
						'storage_table'     => array(
							'type'    => 'string',
							'label'   => 'Blocked client table',
							'default' => 'basic_firewall_blocked',
						),
						'offenses_table'    => array(
							'type'    => 'string',
							'label'   => 'Offense history table',
							'default' => 'basic_firewall_offenses',
						),
						'connection_source' => array(
							'type'    => 'string',
							'label'   => 'Where the connection details come from',
							'default' => 'wordpress',
							'choices' => array( 'wordpress', 'dsn', 'parameters', 'preset' ),
						),
						'dsn'               => array(
							'type'    => 'string',
							'label'   => 'Connection DSN',
							'default' => '',
							/*
							 * A DSN embeds the password, so the whole string is a
							 * credential and the export has to strip all of it.
							 * The `parameters` option exists so host and database
							 * name can stay in a diff while only the password
							 * leaves.
							 */
							'secret'  => true,
						),
						'parameters'        => self::connection_parameters(),
					),
				),
			),
		);
	}

	/**
	 * Individual connection parameters.
	 *
	 * @return array<string, mixed>
	 */
	private static function connection_parameters(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Connection parameters',
			'children' => array(
				'driver'   => array(
					'type'    => 'string',
					'label'   => 'Driver',
					'default' => 'pdo_mysql',
					/*
					 * Doctrine driver names, not database names. `mysql` is the
					 * mistake everyone makes and it fails when the connection is
					 * opened rather than when the form is saved.
					 */
					'choices' => array( 'pdo_mysql', 'mysqli', 'pdo_pgsql', 'pgsql', 'sqlsrv', 'oci8', 'sqlite3' ),
				),
				'host'     => array(
					'type'    => 'string',
					'label'   => 'Host',
					'default' => '',
				),
				'port'     => array(
					'type'    => 'int',
					'label'   => 'Port',
					'default' => 0,
					'min'     => 0,
					'max'     => 65535,
				),
				'dbname'   => array(
					'type'    => 'string',
					'label'   => 'Database name',
					'default' => '',
				),
				'user'     => array(
					'type'    => 'string',
					'label'   => 'User',
					'default' => '',
				),
				'password' => array(
					'type'    => 'string',
					'label'   => 'Password',
					'default' => '',
					'secret'  => true,
				),
			),
		);
	}

	/**
	 * Challenge settings.
	 *
	 * @return array<string, mixed>
	 */
	private static function challenge_section(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Challenge settings',
			'children' => array(
				'provider'         => array(
					'type'    => 'string',
					'label'   => 'Challenge provider',
					'default' => 'math',
					'choices' => array( 'math', 'altcha', 'turnstile', 'recaptcha' ),
				),
				'secret'           => array(
					'type'    => 'string',
					'label'   => 'Signing secret',
					'default' => '',
					'secret'  => true,
				),
				'path'             => array(
					'type'    => 'string',
					'label'   => 'Path the interstitial form posts to',
					'default' => '/basic-firewall/challenge',
				),
				'cookie_name'      => array(
					'type'    => 'string',
					'label'   => 'Pass token cookie name',
					'default' => 'bfw_pass',
				),
				'header_name'      => array(
					'type'    => 'string',
					'label'   => 'Pass token header name',
					'default' => 'X-Firewall-Pass',
				),
				'audience'         => array(
					'type'    => 'string',
					'label'   => 'Token audience',
					'default' => '',
				),
				'provider_options' => array(
					'type'     => 'map',
					'label'    => 'Provider specific options',
					/*
					 * Keyed by provider rather than flat. Three of the four
					 * providers accept a widget_src, and a flat mapping would make
					 * them share one value -- carrying ALTCHA's script URL into a
					 * Turnstile widget.
					 */
					'children' => array(
						'altcha'    => array(
							'type'     => 'map',
							'children' => array(
								'widget_src'       => array(
									'type'    => 'string',
									'label'   => 'ALTCHA widget script URL',
									'default' => '',
								),
								'widget_integrity' => array(
									'type'    => 'string',
									'label'   => 'Subresource Integrity digest',
									'default' => '',
								),
							),
						),
						'turnstile' => array(
							'type'     => 'map',
							'children' => array(
								'site_key'       => array(
									'type'    => 'string',
									'label'   => 'Site key',
									'default' => '',
									/*
									 * Not secret: the site key is rendered into the
									 * page source, so redacting it on export would
									 * protect nothing and break the receiving site.
									 */
								),
								'secret_key'     => array(
									'type'    => 'string',
									'label'   => 'Secret key',
									'default' => '',
									'secret'  => true,
								),
								'theme'          => array(
									'type'    => 'string',
									'label'   => 'Widget theme',
									'default' => 'auto',
									'choices' => array( 'auto', 'light', 'dark' ),
								),
								'widget_src'     => array(
									'type'    => 'string',
									'label'   => 'Widget script URL',
									'default' => '',
								),
								'timeout'        => array(
									'type'    => 'int',
									'label'   => 'Verification timeout in seconds',
									'default' => 5,
									'min'     => 1,
									'max'     => 120,
								),
								'on_error'       => array(
									'type'    => 'string',
									'label'   => 'What to do when verification cannot be reached',
									/*
									 * Rejects by default. Letting visitors through
									 * means an outage at the vendor switches the
									 * challenge off rather than taking the page
									 * down -- a real choice, but not a silent one.
									 */
									'default' => 'fail',
									'choices' => array( 'fail', 'pass' ),
								),
								'send_remoteip'  => array(
									'type'    => 'bool',
									'label'   => "Forward the client IP to Cloudflare",
									'default' => false,
								),
							),
						),
						'recaptcha' => array(
							'type'     => 'map',
							'children' => array(
								'site_key'          => array(
									'type'    => 'string',
									'label'   => 'Site key',
									'default' => '',
								),
								'secret_key'        => array(
									'type'    => 'string',
									'label'   => 'Secret key',
									'default' => '',
									'secret'  => true,
								),
								'version'           => array(
									'type'    => 'string',
									'label'   => 'Version',
									'default' => 'v2',
									'choices' => array( 'v2', 'v3' ),
								),
								'theme'             => array(
									'type'    => 'string',
									'label'   => 'Widget theme, v2 only',
									'default' => 'light',
									'choices' => array( 'light', 'dark' ),
								),
								'size'              => array(
									'type'    => 'string',
									'label'   => 'Widget size, v2 only',
									'default' => 'normal',
									'choices' => array( 'normal', 'compact' ),
								),
								'min_score'         => array(
									'type'    => 'float',
									'label'   => 'Minimum passing score, v3 only',
									'default' => 0.5,
									'min'     => 0.0,
									'max'     => 1.0,
								),
								'action'            => array(
									'type'    => 'string',
									'label'   => 'Action name bound to the token, v3 only',
									'default' => 'firewall',
								),
								'widget_src'        => array(
									'type'    => 'string',
									'label'   => 'Widget script URL',
									'default' => '',
								),
								'timeout'           => array(
									'type'    => 'int',
									'label'   => 'Verification timeout in seconds',
									'default' => 5,
									'min'     => 1,
									'max'     => 120,
								),
								'on_error'          => array(
									'type'    => 'string',
									'label'   => 'What to do when verification cannot be reached',
									'default' => 'fail',
									'choices' => array( 'fail', 'pass' ),
								),
								'send_remoteip'     => array(
									'type'    => 'bool',
									'label'   => 'Forward the client IP to Google',
									'default' => false,
								),
								'use_recaptcha_net' => array(
									'type'    => 'bool',
									'label'   => 'Serve and verify via recaptcha.net instead of google.com',
									'default' => false,
								),
							),
						),
					),
				),
			),
		);
	}

	/**
	 * Cross-cutting logging settings.
	 *
	 * @return array<string, mixed>
	 */
	private static function logging_section(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Logging settings',
			'children' => array(
				'redact_extra'  => array(
					'type'    => 'list',
					'label'   => 'Additional request variables to redact from logs',
					'default' => array(),
					'of'      => array(
						'type'    => 'string',
						'default' => '',
					),
				),
				'to_wordpress'  => array(
					'type'    => 'bool',
					'label'   => 'Also send firewall events to WordPress',
					'default' => false,
				),
				'wp_level'      => array(
					'type'    => 'string',
					'label'   => 'Minimum severity forwarded to WordPress',
					'default' => 'warning',
					'choices' => array( 'debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency' ),
				),
			),
		);
	}

	/**
	 * One log handler.
	 *
	 * @return array<string, mixed>
	 */
	private static function log_handler(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Log handler',
			'children' => array(
				'type'           => array(
					'type'    => 'string',
					'label'   => 'Handler type',
					'default' => 'rotating_file',
					'choices' => array( 'rotating_file', 'stream', 'error_log', 'database' ),
				),
				'enabled'        => array(
					'type'    => 'bool',
					'label'   => 'Enabled',
					'default' => true,
				),
				'level'          => array(
					'type'    => 'string',
					'label'   => 'Minimum level',
					/*
					 * warning, not debug. debug costs roughly 100 KB per allowed
					 * request on a file handler -- about 97 MB per thousand
					 * requests -- on the host most likely to be short of I/O in
					 * the first place. The admin screen warns at the point the
					 * level is chosen.
					 */
					'default' => 'warning',
					'choices' => array( 'debug', 'info', 'notice', 'warning', 'error', 'critical', 'alert', 'emergency' ),
				),
				'path'           => array(
					'type'    => 'string',
					'label'   => 'Log file path',
					'default' => 'private://logs/firewall.log',
				),
				'max_files'      => array(
					'type'    => 'int',
					'label'   => 'Days of log files to keep',
					'default' => 14,
					'min'     => 0,
				),
				'table'          => array(
					'type'    => 'string',
					'label'   => 'Log table',
					'default' => 'basic_firewall_log',
				),
				'connection_source' => array(
					'type'    => 'string',
					'label'   => 'Where the connection details come from',
					'default' => 'wordpress',
					'choices' => array( 'wordpress', 'dsn', 'parameters' ),
				),
				'dsn'            => array(
					'type'    => 'string',
					'label'   => 'Connection DSN',
					'default' => '',
					'secret'  => true,
				),
				'parameters'     => self::connection_parameters(),
				'retain_days'    => array(
					'type'    => 'int',
					'label'   => 'Keep history for this many days, 0 to keep everything',
					'default' => 30,
					'min'     => 0,
				),
				'buffered'       => array(
					'type'    => 'bool',
					'label'   => 'Hold records and write them in one go',
					/*
					 * On. Unbuffered means one insert per record while the request
					 * is being served, and the requests producing the most records
					 * are the ones already under attack. The cost is that a fatal
					 * error loses that request's buffered rows.
					 */
					'default' => true,
				),
			),
		);
	}

	/**
	 * One rule.
	 *
	 * `settings` is intentionally untyped here and validated by the rule type.
	 *
	 * @return array<string, mixed>
	 */
	private static function rule(): array {
		return array(
			'type'     => 'map',
			'label'    => 'Firewall rule',
			'children' => array(
				'id'          => array(
					'type'    => 'string',
					'label'   => 'Identifier',
					'default' => '',
				),
				'type'        => array(
					'type'    => 'string',
					'label'   => 'Rule type',
					'default' => '',
				),
				'label'       => array(
					'type'    => 'string',
					'label'   => 'Label',
					'default' => '',
				),
				'enabled'     => array(
					'type'    => 'bool',
					'label'   => 'Enabled',
					'default' => true,
				),
				'response'    => array(
					'type'    => 'string',
					'label'   => 'Response',
					'default' => 'block',
					'choices' => array( 'allow', 'challenge', 'block' ),
				),
				'weight'      => array(
					'type'    => 'int',
					'label'   => 'Weight',
					'default' => 0,
					'min'     => -1000,
					'max'     => 1000,
				),
				'status_code'       => array(
					'type'    => 'int',
					'label'   => 'HTTP status code, 0 to use the site-wide code',
					/*
					 * Zero, and zero is written into the compiled file rather
					 * than omitted. The library reads
					 * `metadata['status_code'] ?? 400`, so an absent key does not
					 * mean "unset" -- it means 400 Bad Request. Only an explicit
					 * zero makes the library fall through to the site-wide code
					 * that the General screen promises.
					 */
					'default' => 0,
					'min'     => 0,
					'max'     => 599,
				),
				'challenge_provider' => array(
					'type'    => 'string',
					'label'   => 'Challenge provider for this rule, blank for the site default',
					'default' => '',
				),
				'expiration'  => array(
					'type'    => 'int',
					'label'   => 'Block duration, or challenge re-issue interval, in seconds',
					/*
					 * One hour. Zero is a legitimate value that means opposite
					 * things by response -- permanent for a block, "fall back to
					 * 3600" for a challenge -- so it is never the default, and the
					 * rule form warns when it is saved on a block rule.
					 */
					'default' => 3600,
					'min'     => 0,
				),
				'description' => array(
					'type'    => 'text',
					'label'   => 'Description',
					'default' => '',
				),
				'settings'    => array(
					'type'    => 'raw',
					'label'   => 'Rule type settings',
					'default' => array(),
				),
			),
		);
	}

	/**
	 * The default settings document, built from the schema's own defaults.
	 *
	 * There is deliberately no second copy of the defaults anywhere. A shipped
	 * defaults file that drifts from the schema is a bug that only appears on
	 * fresh installs, which is where it is least likely to be noticed.
	 *
	 * @return array<string, mixed>
	 */
	public static function defaults(): array {
		return self::defaults_for( self::definition() );
	}

	/**
	 * Build the default value for one node.
	 *
	 * @param array<string, mixed> $node Schema node.
	 *
	 * @return mixed
	 */
	private static function defaults_for( array $node ) {
		if ( 'map' === ( $node['type'] ?? '' ) ) {
			$out = array();

			foreach ( $node['children'] ?? array() as $key => $child ) {
				$out[ $key ] = self::defaults_for( $child );
			}

			return $out;
		}

		return $node['default'] ?? null;
	}

	/**
	 * Every path in the schema whose value is a credential.
	 *
	 * Paths use dotted notation with `*` for a list index, which is what the
	 * exporter walks. Derived from the schema rather than hand-listed, so a
	 * field added with `secret => true` is redacted the day it is added.
	 *
	 * @return list<string>
	 */
	public static function secret_paths(): array {
		$found = array();
		self::collect_secrets( self::definition(), '', $found );

		return $found;
	}

	/**
	 * Recursive worker for secret_paths().
	 *
	 * @param array<string, mixed> $node  Schema node.
	 * @param string               $path  Path accumulated so far.
	 * @param list<string>         $found Collected paths, by reference.
	 */
	private static function collect_secrets( array $node, string $path, array &$found ): void {
		if ( ! empty( $node['secret'] ) && '' !== $path ) {
			$found[] = $path;
		}

		$type = $node['type'] ?? '';

		if ( 'map' === $type ) {
			foreach ( $node['children'] ?? array() as $key => $child ) {
				self::collect_secrets( $child, '' === $path ? (string) $key : $path . '.' . $key, $found );
			}

			return;
		}

		if ( 'list' === $type && isset( $node['of'] ) && is_array( $node['of'] ) ) {
			self::collect_secrets( $node['of'], $path . '.*', $found );
		}
	}
}
