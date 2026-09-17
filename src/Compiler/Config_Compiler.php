<?php
/**
 * Compiles settings into the library's native configuration.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Compiler;

use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Library_Capabilities;
use Kanopi\BasicFirewall\Install\Challenge_Secret;
use Kanopi\BasicFirewall\Plugin;
use Symfony\Component\Yaml\Yaml;

/**
 * Turns the settings option into the library's own configuration format.
 *
 * The compiled result is written to one file in the private directory and that
 * file is what the firewall reads at runtime, so evaluating a request costs one
 * file read -- no option lookup, no database query, no rule objects rebuilt from
 * an array on every hit.
 *
 * **The compiled file is a cache.** It is regenerated whenever settings are
 * saved, whenever a document is imported, and on demand. It is safe to delete,
 * and it carries a DO NOT EDIT header because anything changed in it is
 * overwritten on the next rebuild.
 *
 * The one part worth reading closely is what does *not* go in it. WordPress's
 * database credentials are never written here. The compiler records the
 * property-access paths where a connection belongs and the runner injects live
 * credentials at those paths on every request. See Database_Credentials for why
 * that is a requirement rather than a nicety.
 */
final class Config_Compiler {

	/**
	 * Paths in the compiled array where live credentials must be injected.
	 *
	 * Symfony property-access syntax, which is what the library's runtime
	 * override mechanism takes.
	 *
	 * @var list<string>
	 */
	private array $connection_paths = array();

	/**
	 * Problems encountered while compiling.
	 *
	 * @var list<string>
	 */
	private array $problems = array();

	/**
	 * Compile the current settings.
	 *
	 * @return array<string, mixed>
	 */
	public function compile(): array {
		$this->connection_paths = array();
		$this->problems         = array();

		$plugin   = Plugin::instance();
		$settings = $plugin->settings();

		$rules = $this->compile_rules( (array) $settings->get( 'rules', array() ) );

		$compiled = array();

		/*
		 * Presets are included by reference rather than copied in. The library's
		 * loader appends their plugin entries to ours rather than replacing
		 * them, so locally configured rules survive alongside a preset's, and an
		 * exported document records only which presets are on -- a preset's
		 * several hundred patterns never appear in a diff.
		 */
		$presets = $plugin->presets()->resolve_paths( (array) $settings->get( 'presets', array() ) );

		foreach ( $plugin->presets()->problems() as $problem ) {
			$this->problems[] = $problem;
		}

		if ( array() !== $presets ) {
			$compiled['configs'] = $presets;
		}

		/*
		 * A rate limit's counter connection is emitted by its rule type, which
		 * has no idea what index it will occupy in the plugin list. That index
		 * only exists here, so this is where a WordPress-backed connection is
		 * lifted out of the file and recorded for the runner to inject.
		 */
		foreach ( $rules as $delta => $rule ) {
			$storage = $rule['metadata']['storage'] ?? null;

			if ( ! is_array( $storage ) || true !== ( $storage['config']['connection']['__wordpress'] ?? false ) ) {
				continue;
			}

			unset( $rules[ $delta ]['metadata']['storage']['config']['connection'] );

			$this->connection_paths[] = sprintf( '[plugins][%d][metadata][storage][config][connection]', $delta );
		}

		$compiled += array(
			'global'  => $this->compile_global( (array) $settings->get( 'global', array() ) ),
			'storage' => $this->compile_storage( (array) $settings->get( 'storage', array() ) ),
			'plugins' => array_values( $rules ),
		);

		$logger = $this->compile_logger( (array) $settings->get( 'logger', array() ) );

		if ( array() !== $logger ) {
			$compiled['logger'] = $logger;
		}

		/*
		 * The library throws at startup when a challenge plugin exists without a
		 * secret, and this plugin fails open on that -- which would leave the
		 * site with no firewall running at all rather than one broken rule. So
		 * the section is emitted only when something actually needs it, and
		 * presets count: one of them ships `response: challenge`.
		 */
		if ( $this->needs_challenge( $rules, (array) $settings->get( 'presets', array() ) ) ) {
			$compiled['challenge'] = $this->compile_challenge( (array) $settings->get( 'challenge', array() ) );
		}

		return $this->apply_advanced_yaml( $compiled, (string) $settings->get( 'advanced_yaml', '' ) );
	}

	/**
	 * Compile the global section.
	 *
	 * @param array<string, mixed> $section Stored global settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_global( array $section ): array {
		$compiled = array(
			'mode'                    => $this->resolve_mode( $section ),
			'banning_status_code'     => (int) ( $section['banning_status_code'] ?? 403 ),
			'banning_message'         => (string) ( $section['banning_message'] ?? 'Request blocked.' ),
			'require_trusted_proxies' => (bool) ( $section['require_trusted_proxies'] ?? false ),

			/*
			 * Without this the library logs a failed config load and starts with
			 * whatever parsed -- which for a single-file setup like ours means an
			 * empty ruleset that allows every request and looks like success.
			 * With it, the library refuses to start, which the runner catches,
			 * logs as an error, and then fails open on. Traffic is treated the
			 * same either way; this decides whether anybody finds out.
			 */
			'require_config'          => (bool) ( $section['require_config'] ?? true ),
		);

		/*
		 * Three states, and "absent" is one of them. The library reads an absent
		 * key as "posture unknown" and keeps warning, FALSE as "asserted: no
		 * proxy" and goes silent, TRUE as "asserted: there is one" and escalates
		 * a missing trusted-proxy list to an error.
		 *
		 * Emitting FALSE for somebody who never answered would silence a
		 * security warning on their behalf, so the key is written only once they
		 * have answered.
		 */
		$behind = (string) ( $section['behind_proxy'] ?? 'unknown' );

		if ( 'no' === $behind || 'yes' === $behind ) {
			$compiled['behind_proxy'] = 'yes' === $behind;
		}

		$repeat = (int) ( $section['repeat_offender_status'] ?? 0 );

		if ( $repeat > 0 ) {
			$compiled['repeat_offender_status'] = $repeat;
		}

		$add_to_expire = (int) ( $section['add_to_expire'] ?? 0 );

		if ( $add_to_expire > 0 ) {
			$compiled['add_to_expire'] = $add_to_expire;
		}

		$escalation = $this->compile_escalation( (array) ( $section['blocking_escalation'] ?? array() ) );

		if ( array() !== $escalation ) {
			$compiled['blocking_escalation'] = $escalation;
		}

		return $compiled;
	}

	/**
	 * Resolve the operating mode, honouring a wp-config.php override.
	 *
	 * @param array<string, mixed> $section Stored global settings.
	 */
	private function resolve_mode( array $section ): string {
		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$override = constant( 'BASIC_FIREWALL_MODE' );

			if ( is_string( $override ) && isset( Library_Map::MODES[ $override ] ) ) {
				return $override;
			}
		}

		$mode = (string) ( $section['mode'] ?? 'log' );

		return isset( Library_Map::MODES[ $mode ] ) ? $mode : 'log';
	}

	/**
	 * Compile the escalation stages.
	 *
	 * @param array<int, mixed> $stages Stored stages.
	 *
	 * @return list<array<string, int>>
	 */
	private function compile_escalation( array $stages ): array {
		$compiled = array();

		foreach ( $stages as $stage ) {
			if ( ! is_array( $stage ) ) {
				continue;
			}

			$window = (int) ( $stage['window'] ?? 0 );

			if ( $window <= 0 ) {
				// The library skips a stage without a window, so dropping it
				// here keeps the compiled file honest about what will run.
				continue;
			}

			$entry = array(
				'window'  => $window,
				'offense' => (int) ( $stage['offense'] ?? 0 ),
			);

			/*
			 * Omitting `duration` makes the library fall back to the matching
			 * rule's own duration, which is meaningfully different from zero --
			 * zero means block permanently.
			 */
			if ( empty( $stage['use_plugin_default'] ) ) {
				$entry['duration'] = (int) ( $stage['duration'] ?? 0 );
			}

			$compiled[] = $entry;
		}

		usort( $compiled, static fn ( array $a, array $b ): int => $a['window'] <=> $b['window'] );

		return $compiled;
	}

	/**
	 * Compile the blocked-client storage section.
	 *
	 * @param array<string, mixed> $storage Stored storage settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_storage( array $storage ): array {
		$backend = (string) ( $storage['backend'] ?? 'file' );

		if ( 'database' === $backend ) {
			$compiled = $this->compile_database_storage( (array) ( $storage['database'] ?? array() ) );

			if ( null !== $compiled ) {
				return $compiled;
			}

			$this->problems[] = __( 'Database storage is selected but no usable connection could be built. Falling back to file storage so the firewall still starts.', 'basic-firewall' );

			$backend = 'file';
		}

		if ( 'file' === $backend ) {
			$paths = Plugin::instance()->paths();
			$file  = (array) ( $storage['file'] ?? array() );

			/*
			 * Written as the administrator typed it. A relative filename stays
			 * relative: the library resolves these two keys against the
			 * directory holding the file that named them, which is the private
			 * directory, so the result is identical and the document says what
			 * the form said. See Paths::portable().
			 */
			$storage_file = $paths->portable( (string) ( $file['storage_file'] ?? 'blocked.data' ) );

			if ( '' === $storage_file ) {
				$storage_file = 'blocked.data';
			}

			$offense_file = $paths->portable( (string) ( $file['offense_file'] ?? '' ) );

			$config = array( 'storage_file' => $storage_file );

			/*
			 * Derived rather than omitted when the field is blank. Leaving the
			 * key out hands the decision to whatever default the library
			 * currently has -- and that default moved in 2.22.0: it used to come
			 * from the *directory* holding the storage file, which meant two
			 * stores in one directory shared a single offense history and
			 * escalated each other's clients.
			 */
			$config['offense_file'] = '' !== $offense_file
				? $offense_file
				: $storage_file . '.offenses';

			return array(
				'type'   => Library_Map::STORAGE['file'],
				'config' => $config,
			);
		}

		/*
		 * In-memory. Not offered as a choice on the storage screen -- it
		 * discards every block when the request ends, so the firewall would
		 * evaluate rules and throw the result away while reporting itself as
		 * enabled. The backend still exists because the request tester uses it
		 * deliberately, which is how a test leaves no trace.
		 */
		return array( 'type' => Library_Map::STORAGE['memory'] );
	}

	/**
	 * Compile database storage, or null if no connection can be built.
	 *
	 * @param array<string, mixed> $database Stored database settings.
	 *
	 * @return array<string, mixed>|null
	 */
	private function compile_database_storage( array $database ): ?array {
		$source      = (string) ( $database['connection_source'] ?? 'wordpress' );
		$credentials = new Database_Credentials();
		$uses_wp     = 'wordpress' === $source;

		$storage_table  = (string) ( $database['storage_table'] ?? 'basic_firewall_blocked' );
		$offenses_table = (string) ( $database['offenses_table'] ?? 'basic_firewall_offenses' );

		/*
		 * A preset supplies the connection itself. Emitting one here would be
		 * merged over by nothing -- this plugin's file is the base of the merge,
		 * so any key it writes survives whatever the preset sets alongside it --
		 * and injecting WordPress's credentials would replace the preset's
		 * connection outright, because overrides are applied after every file
		 * has been merged. Contributing nothing is the only way the preset's
		 * connection actually reaches the backend.
		 */
		if ( 'preset' === $source ) {
			return array(
				'type'   => Library_Map::STORAGE['database'],
				'config' => array(
					'storage_table'  => $storage_table,
					'offenses_table' => $offenses_table,
				),
			);
		}

		$connection = match ( $source ) {
			'wordpress'  => $credentials->get_connection_parameters(),
			'parameters' => $this->compile_connection_parameters( (array) ( $database['parameters'] ?? array() ) ),
			default      => '' === trim( (string) ( $database['dsn'] ?? '' ) )
				? array()
				: array( 'dsn' => trim( (string) $database['dsn'] ) ),
		};

		if ( array() === $connection ) {
			return null;
		}

		$config = array(
			// Prefixed only when the tables live in WordPress's own database. A
			// supplied DSN points at a schema somebody named themselves, and
			// prefixing it would rename a table they created.
			'storage_table'  => $uses_wp ? $credentials->prefix_table( $storage_table ) : $storage_table,
			'offenses_table' => $uses_wp ? $credentials->prefix_table( $offenses_table ) : $offenses_table,
		);

		if ( $uses_wp ) {
			// Recorded, not written. See the class docblock.
			$this->connection_paths[] = '[storage][config][connection]';
		} else {
			$config['connection'] = $connection;
		}

		return array(
			'type'   => Library_Map::STORAGE['database'],
			'config' => $config,
		);
	}

	/**
	 * Compile individual connection parameters.
	 *
	 * @param array<string, mixed> $parameters Stored parameters.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_connection_parameters( array $parameters ): array {
		$compiled = array();

		foreach ( array( 'driver', 'host', 'dbname', 'user', 'password' ) as $key ) {
			$value = trim( (string) ( $parameters[ $key ] ?? '' ) );

			if ( '' !== $value ) {
				$compiled[ $key ] = $value;
			}
		}

		$port = (int) ( $parameters['port'] ?? 0 );

		if ( $port > 0 ) {
			$compiled['port'] = $port;
		}

		// A driver and a database name are the minimum that can open anything.
		return isset( $compiled['driver'], $compiled['dbname'] ) ? $compiled : array();
	}

	/**
	 * Compile the rules into library plugin entries.
	 *
	 * @param array<int, mixed> $rules Stored rules.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function compile_rules( array $rules ): array {
		$registry     = Plugin::instance()->rule_types();
		$capabilities = new Library_Capabilities();
		$compiled     = array();

		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['enabled'] ) ) {
				continue;
			}

			$type = $registry->get( (string) ( $rule['type'] ?? '' ) );

			if ( null === $type ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: rule type. */
					__( 'Rule "%1$s" has an unknown type "%2$s" and was skipped.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					(string) ( $rule['type'] ?? '?' )
				);

				continue;
			}

			/*
			 * A rule whose type the installed library cannot provide is skipped
			 * with a warning rather than compiled into a plugin entry naming a
			 * class that does not exist. The library would skip such an entry
			 * silently, which is the failure this plugin exists to avoid.
			 */
			if ( ! $type->is_available() ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: rule type name. */
					__( 'Rule "%1$s" needs the %2$s rule type, which the installed firewall library cannot provide. It was skipped, so it is not being enforced.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					$type->label()
				);

				continue;
			}

			/*
			 * A response the installed library cannot honour is skipped, loudly.
			 *
			 * `redirect` and `mark` arrived in library 2.26.0. An older library
			 * partitions plugins by response and simply has no bucket for
			 * either, so a rule carrying one is not rejected -- it is never
			 * evaluated. That is the silent-no-op this plugin exists to avoid,
			 * and it is reachable without anybody making a mistake: importing a
			 * document from a site on a newer library does it.
			 */
			$response = (string) ( $rule['response'] ?? 'block' );

			if ( in_array( $response, array( 'redirect', 'mark', 'record' ), true ) && ! $capabilities->has_soft_responses() ) {
				$this->problems[] = sprintf(
					/* translators: 1: rule identifier, 2: response name. */
					__( 'Rule "%1$s" responds with "%2$s", which needs kanopi/firewall 2.26.0 or later. The installed library would never evaluate it, so it was skipped rather than compiled into a rule that silently does nothing.', 'basic-firewall' ),
					(string) ( $rule['id'] ?? '?' ),
					$response
				);

				continue;
			}

			$compiled[] = $type->compile( $rule );
		}

		// Lower weights first, matching the order the library evaluates in.
		usort(
			$compiled,
			static fn ( array $a, array $b ): int => ( $a['weight'] ?? 0 ) <=> ( $b['weight'] ?? 0 )
		);

		return $compiled;
	}

	/**
	 * Whether a challenge section has to be emitted.
	 *
	 * @param list<array<string, mixed>> $rules   Compiled rules.
	 * @param list<string>               $presets Enabled preset names.
	 */
	private function needs_challenge( array $rules, array $presets ): bool {
		foreach ( $rules as $rule ) {
			if ( 'challenge' === ( $rule['response'] ?? '' ) ) {
				return true;
			}
		}

		return Plugin::instance()->presets()->requires_challenge( $presets );
	}

	/**
	 * Compile the challenge section.
	 *
	 * @param array<string, mixed> $challenge Stored challenge settings.
	 *
	 * @return array<string, mixed>
	 */
	private function compile_challenge( array $challenge ): array {
		$provider = (string) ( $challenge['provider'] ?? 'math' );

		$compiled = array(
			'provider'    => $provider,
			'path'        => (string) ( $challenge['path'] ?? '/basic-firewall/challenge' ),
			'cookie_name' => (string) ( $challenge['cookie_name'] ?? 'bfw_pass' ),
			'header_name' => (string) ( $challenge['header_name'] ?? 'X-Firewall-Pass' ),

			/*
			 * A ceiling as well as a default, which is the whole point of it.
			 *
			 * Needs library 2.30.0. Before it, the lifetime that signs a pass
			 * token was whatever the interstitial's POST body asked for --
			 * solve one arithmetic puzzle, post a lifetime of thirty-one years,
			 * and hold a signed exemption from every challenge rule for three
			 * decades. The signature was valid; it covered the number the
			 * client chose.
			 *
			 * Written out rather than left to the library's own default so the
			 * value is visible in the compiled file and on the screen that sets
			 * it, because a rule asking for longer than this is silently
			 * granted this instead.
			 */
			'ttl'         => max( 60, (int) ( $challenge['ttl'] ?? 3600 ) ),
		);

		$secret = Challenge_Secret::resolve();

		if ( null === $secret ) {
			$this->problems[] = __( 'A rule is set to challenge but there is no signing secret. The firewall will refuse to start, and every rule stops being enforced.', 'basic-firewall' );
		} else {
			$compiled['secret'] = $secret;
		}

		$audience = trim( (string) ( $challenge['audience'] ?? '' ) );

		if ( '' !== $audience ) {
			$compiled['audience'] = $audience;
		}

		$options = (array) ( $challenge['provider_options'][ $provider ] ?? array() );

		if ( array() !== $options ) {
			$compiled['options'] = array_filter(
				$options,
				static fn ( $value ): bool => '' !== $value && null !== $value
			);
		}

		return $compiled;
	}

	/**
	 * Compile the log handlers.
	 *
	 * @param array<int, mixed> $handlers Stored handlers.
	 *
	 * @return list<array<string, mixed>>
	 */
	private function compile_logger( array $handlers ): array {
		$compiled    = array();
		$levels      = Library_Map::log_levels();
		$paths       = Plugin::instance()->paths();
		$credentials = new Database_Credentials();

		foreach ( $handlers as $handler ) {
			if ( ! is_array( $handler ) || empty( $handler['enabled'] ) ) {
				continue;
			}

			$type = (string) ( $handler['type'] ?? 'rotating_file' );

			if ( ! isset( Library_Map::LOG_HANDLERS[ $type ] ) ) {
				continue;
			}

			$level = $levels[ (string) ( $handler['level'] ?? 'warning' ) ] ?? $levels['warning'];

			if ( in_array( $type, Library_Map::LOG_HANDLERS_KEYED, true ) ) {
				/*
				 * Every key here is the library's own spelling, and two of them
				 * were not.
				 *
				 * The handler reads `buffer` and `retention_days`; this wrote
				 * `buffered` and `retain_days`. A declaration is read with array
				 * keys, so neither was an error -- both were ignored and the
				 * defaults applied. The Buffering checkbox therefore did
				 * nothing and the handler always buffered, and "Keep history
				 * for" did nothing and retention stayed at zero, which is the
				 * table that only grows the field's own help text warns about.
				 */
				$options = array(
					'table'                    => 'wordpress' === ( $handler['connection_source'] ?? 'wordpress' )
						? $credentials->prefix_table( (string) ( $handler['table'] ?? 'basic_firewall_log' ) )
						: (string) ( $handler['table'] ?? 'basic_firewall_log' ),
					'level'                    => $level,
					'buffer'                   => ! empty( $handler['buffered'] ),
					'retention_days'           => (int) ( $handler['retain_days'] ?? 30 ),

					/*
					 * The library checks its schema on one write in a hundred,
					 * which is the right cost on a table that exists and the
					 * wrong behaviour on one that does not: a fresh install
					 * loses roughly its first hundred events while the handler
					 * waits for its turn to notice there is nowhere to put
					 * them. Checked on every write for the first few instead --
					 * the check is one query against a table this handler is
					 * about to write to anyway.
					 */
					'schema_check_probability' => 1.0,
				);

				$entry = array(
					'class' => Library_Map::LOG_HANDLERS[ $type ],
					'args'  => array( $options ),
				);

				if ( 'wordpress' === ( $handler['connection_source'] ?? 'wordpress' ) ) {
					$this->connection_paths[] = sprintf( '[logger][%d][args][0][connection]', count( $compiled ) );
				} elseif ( '' !== trim( (string) ( $handler['dsn'] ?? '' ) ) ) {
					$entry['args'][0]['connection'] = array( 'dsn' => trim( (string) $handler['dsn'] ) );
				}

				$compiled[] = $entry;

				continue;
			}

			/*
			 * Positional constructor arguments, ordered per handler.
			 *
			 * The path is written as typed, for the same reason the storage
			 * file is: the library resolves a relative `args.0` on a stream or
			 * rotating-file handler against the directory holding the config
			 * that named it, missing file and all. See Paths::portable().
			 */
			$log_path = $paths->portable( (string) ( $handler['path'] ?? 'logs/firewall.log' ) );

			if ( '' === $log_path ) {
				$log_path = 'logs/firewall.log';
			}

			$args = match ( $type ) {
				'rotating_file' => array(
					$log_path,
					(int) ( $handler['max_files'] ?? 14 ),
					$level,
				),
				'stream'        => array(
					$log_path,
					$level,
				),
				// ErrorLogHandler takes a message type first, then the level.
				default         => array( 0, $level ),
			};

			$compiled[] = array(
				'class' => Library_Map::LOG_HANDLERS[ $type ],
				'args'  => $args,
			);
		}

		return $compiled;
	}

	/**
	 * Merge the advanced YAML over the compiled configuration.
	 *
	 * For conditions the forms cannot express -- groups nested inside groups --
	 * and for anything the library gains before this plugin has a screen for it.
	 *
	 * @param array<string, mixed> $compiled Compiled configuration.
	 * @param string               $yaml     Raw YAML.
	 *
	 * @return array<string, mixed>
	 */
	private function apply_advanced_yaml( array $compiled, string $yaml ): array {
		if ( '' === trim( $yaml ) ) {
			return $compiled;
		}

		try {
			$parsed = Yaml::parse( $yaml );
		} catch ( \Throwable $e ) {
			$this->problems[] = sprintf(
				/* translators: %s: parser error message. */
				__( 'The advanced YAML could not be parsed and was ignored: %s', 'basic-firewall' ),
				$e->getMessage()
			);

			return $compiled;
		}

		if ( ! is_array( $parsed ) ) {
			return $compiled;
		}

		return self::merge_deep( $compiled, $parsed );
	}

	/**
	 * Recursively merge, with the override winning.
	 *
	 * A list is replaced rather than concatenated: somebody writing a `plugins`
	 * list in the advanced screen means "these", not "these as well as the ones
	 * I configured elsewhere".
	 *
	 * @param array<mixed> $base     Base array.
	 * @param array<mixed> $override Override array.
	 *
	 * @return array<mixed>
	 */
	private static function merge_deep( array $base, array $override ): array {
		foreach ( $override as $key => $value ) {
			if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) && ! array_is_list( $value ) ) {
				$base[ $key ] = self::merge_deep( $base[ $key ], $value );

				continue;
			}

			$base[ $key ] = $value;
		}

		return $base;
	}

	/**
	 * Property-access paths where live credentials must be injected.
	 *
	 * @return list<string>
	 */
	public function connection_paths(): array {
		return $this->connection_paths;
	}

	/**
	 * Problems encountered during the last compile.
	 *
	 * @return list<string>
	 */
	public function problems(): array {
		return $this->problems;
	}
}
