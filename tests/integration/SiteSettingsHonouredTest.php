<?php
/**
 * Every site-wide setting, and every rule-level field, against the library.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Install\Challenge_Secret;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\Firewall\Challenge\RecaptchaChallengeProvider;
use Kanopi\Firewall\Challenge\TurnstileChallengeProvider;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\ConfigurationException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Logging\Handler\DeferredHandler;
use Kanopi\Firewall\Logging\LoggingFactory;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\RedisStorage;
use Kanopi\Firewall\Utility\RequestPath;
use Monolog\Handler\ErrorLogHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\StreamHandler;
use Symfony\Component\Cache\Adapter\ApcuAdapter;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Component\HttpFoundation\Request;

/**
 * That the library does what the General, Storage, Logging and Challenge
 * screens -- and the rule-level fields of the rule screen -- say it will.
 *
 * The headline defect here was the challenge section. Provider options were
 * compiled as `challenge.options`; the library reads
 * `challenge.provider_options.<provider>`. Turnstile and reCAPTCHA refuse to
 * construct without their keys, so choosing either with any challenge rule in
 * place made the library refuse to start -- and this plugin fails open on
 * that, so nothing at all was enforced while every screen looked configured.
 *
 * As in RuleTypesHonouredTest, the first test enumerates the settings schema
 * and fails on any setting that has no entry below. An entry is one of three
 * things: the test proving the library acts on it; `plugin:` and why the
 * setting never reaches the library at all; or `unapplied:` for a setting that
 * is stored and shown and that nothing yet acts on. The last kind is a known
 * defect written down, so it cannot quietly grow.
 *
 * @covers \Kanopi\BasicFirewall\Compiler\Config_Compiler
 * @covers \Kanopi\BasicFirewall\RuleType\Rule_Type_Base
 */
final class SiteSettingsHonouredTest extends Honoured_Settings {

	/**
	 * Every leaf of the settings schema, and how it is shown to be honoured.
	 *
	 * @var array<string, string>
	 */
	private const COVERAGE = array(
		'enabled'                                         => 'test_enabled',
		'global.bypass_roles'                             => 'test_bypass_roles',
		'global.mode'                                     => 'test_mode',
		'global.panic_file'                               => 'test_panic_file',
		'global.lockdown'                                 => 'test_lockdown',
		'global.lockdown_allow'                           => 'test_lockdown',
		'global.banning_status_code'                      => 'test_banning_response',
		'global.banning_message'                          => 'test_banning_response',
		'global.block_page.enabled'                       => 'test_block_page',
		'global.block_page.title'                         => 'test_block_page',
		'global.block_page.heading'                       => 'test_block_page',
		'global.lockdown_page.enabled'                    => 'test_lockdown_page',
		'global.lockdown_page.title'                      => 'test_lockdown_page',
		'global.lockdown_page.heading'                    => 'test_lockdown_page',
		'global.lockdown_page.message'                    => 'test_lockdown_page',
		'global.pages.lang'                               => 'test_block_page',
		'global.pages.styles'                             => 'test_block_page',
		'global.pages.stylesheet'                         => 'test_block_page',
		'global.banning_json'                             => 'test_banning_json',
		'global.repeat_offender_status'                   => 'test_repeat_offenders',
		'global.add_to_expire'                            => 'test_repeat_offenders',
		'global.behind_proxy'                             => 'test_proxy_posture',
		'global.require_trusted_proxies'                  => 'test_proxy_posture',
		'global.require_config'                           => 'test_require_config',
		'global.blocking_escalation.*.window'             => 'test_blocking_escalation',
		'global.blocking_escalation.*.offense'            => 'test_blocking_escalation',
		'global.blocking_escalation.*.duration'           => 'test_blocking_escalation',
		'global.blocking_escalation.*.use_plugin_default' => 'test_blocking_escalation',
		'cache.backend'                                   => 'test_cache_backend',
		'cache.directory'                                 => 'test_cache_backend',
		'cache.apcu_ttl'                                  => 'test_apcu_cache',
		'storage.backend'                                 => 'test_file_storage',
		'storage.file.storage_file'                       => 'test_file_storage',
		'storage.file.offense_file'                       => 'test_file_storage',
		'storage.database.storage_table'                  => 'test_database_storage',
		'storage.database.offenses_table'                 => 'test_database_storage',
		'storage.database.connection_source'              => 'test_database_storage',
		'storage.database.dsn'                            => 'test_database_storage',
		'storage.database.parameters.driver'              => 'test_database_storage',
		'storage.database.parameters.host'                => 'test_database_storage',
		'storage.database.parameters.port'                => 'test_database_storage',
		'storage.database.parameters.dbname'              => 'test_database_storage',
		'storage.database.parameters.user'                => 'test_database_storage',
		'storage.database.parameters.password'            => 'test_database_storage',
		'storage.redis.host'                              => 'test_redis_storage',
		'storage.redis.port'                              => 'test_redis_storage',
		'storage.redis.prefix'                            => 'test_redis_storage',
		'storage.redis.username'                          => 'test_redis_storage',
		'storage.redis.password'                          => 'test_redis_storage',
		'storage.record_request.cookies'                  => 'test_record_request',
		'storage.record_request.headers'                  => 'test_record_request',
		'storage.record_request.query'                    => 'test_record_request',
		'storage.record_request.body'                     => 'test_record_request',
		'challenge.provider'                              => 'test_remote_challenge_providers',
		'challenge.secret'                                => 'test_challenge_section',
		'challenge.ttl'                                   => 'test_challenge_section',
		'challenge.path'                                  => 'test_challenge_section',
		'challenge.cookie_name'                           => 'test_challenge_section',
		'challenge.header_name'                           => 'test_challenge_section',
		'challenge.audience'                              => 'test_challenge_section',
		'challenge.page.title'                            => 'test_challenge_page',
		'challenge.page.heading'                          => 'test_challenge_page',
		'challenge.page.intro'                            => 'test_challenge_page',
		'challenge.page.button'                           => 'test_challenge_page',
		'challenge.page.error_message'                    => 'test_challenge_page',
		'challenge.page.lang'                             => 'test_challenge_page',
		'challenge.page.styles'                           => 'test_challenge_page',
		'challenge.page.stylesheet'                       => 'test_challenge_page',
		'challenge.notice'                                => 'test_challenge_page',
		'challenge.provider_options.altcha.widget_src'    => 'test_challenge_section',
		'challenge.provider_options.altcha.widget_integrity' => 'test_challenge_section',
		'challenge.provider_options.turnstile.site_key'   => 'test_remote_challenge_providers',
		'challenge.provider_options.turnstile.secret_key' => 'test_remote_challenge_providers',
		'challenge.provider_options.turnstile.theme'      => 'test_remote_challenge_providers',
		'challenge.provider_options.turnstile.widget_src' => 'test_remote_challenge_providers',
		'challenge.provider_options.turnstile.timeout'    => 'test_remote_challenge_providers',
		'challenge.provider_options.turnstile.on_error'   => 'test_remote_challenge_providers',
		'challenge.provider_options.turnstile.send_remoteip' => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.site_key'   => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.secret_key' => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.version'    => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.theme'      => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.size'       => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.min_score'  => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.action'     => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.widget_src' => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.timeout'    => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.on_error'   => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.send_remoteip' => 'test_remote_challenge_providers',
		'challenge.provider_options.recaptcha.use_recaptcha_net' => 'test_remote_challenge_providers',
		'logging.redact_extra'                            => 'test_redact_extra',
		'logger.*.type'                                   => 'test_log_handlers',
		'logger.*.enabled'                                => 'test_log_handlers',
		'logger.*.level'                                  => 'test_log_handlers',
		'logger.*.path'                                   => 'test_log_handlers',
		'logger.*.max_files'                              => 'test_log_handlers',
		'logger.*.table'                                  => 'test_database_log_handler',
		'logger.*.connection_source'                      => 'test_database_log_handler',
		'logger.*.dsn'                                    => 'test_database_log_handler',
		'logger.*.parameters.driver'                      => 'test_database_log_handler',
		'logger.*.parameters.host'                        => 'test_database_log_handler',
		'logger.*.parameters.port'                        => 'test_database_log_handler',
		'logger.*.parameters.dbname'                      => 'test_database_log_handler',
		'logger.*.parameters.user'                        => 'test_database_log_handler',
		'logger.*.parameters.password'                    => 'test_database_log_handler',
		'logger.*.retain_days'                            => 'test_database_log_handler',
		'logger.*.prune_batch_size'                       => 'test_database_log_handler',
		'logger.*.prune_max_batches'                      => 'test_database_log_handler',
		'logger.*.deferred'                               => 'test_log_handlers',
		'logger.*.buffered'                               => 'test_database_log_handler',
		'sources.cron_interval'                           => 'plugin: how often WordPress cron refreshes lists, never compiled; see LifecycleTest.',
		'rules.*.id'                                      => 'test_rule_identity',
		'rules.*.type'                                    => 'plugin: chooses the rule type; every type is proved in RuleTypesHonouredTest.',
		'rules.*.label'                                   => 'plugin: shown on the screens only.',
		'rules.*.enabled'                                 => 'test_rule_identity',
		'rules.*.response'                                => 'test_rule_responses',
		'rules.*.observe'                                 => 'test_rule_responses',
		'rules.*.weight'                                  => 'test_rule_responses',
		'rules.*.status_code'                             => 'test_banning_response',
		'rules.*.record'                                  => 'test_rule_responses',
		'rules.*.redirect_to'                             => 'test_rule_responses',
		'rules.*.redirect_status'                         => 'test_rule_responses',
		'rules.*.mark_as'                                 => 'test_rule_responses',
		'rules.*.mark_header'                             => 'test_rule_responses',
		'rules.*.challenge_provider'                      => 'test_challenge_section',
		'rules.*.expiration'                              => 'test_blocking_escalation',
		'rules.*.description'                             => 'plugin: shown on the screens only.',
		'rules.*.schedule.timezone'                       => 'test_rule_schedule',
		'rules.*.schedule.days'                           => 'test_rule_schedule',
		'rules.*.schedule.hours'                          => 'test_rule_schedule',
		'rules.*.schedule.from'                           => 'test_rule_schedule',
		'rules.*.schedule.until'                          => 'test_rule_schedule',
		'rules.*.settings'                                => 'plugin: validated by the rule type; every setting is proved in RuleTypesHonouredTest.',
		'presets'                                         => 'plugin: included by reference as the library\'s own files; see Preset handling in LifecycleTest.',
		'advanced_yaml'                                   => 'plugin: merged verbatim over the compiled file; whatever it says is the library\'s own vocabulary.',
	);

	/**
	 * Compiled keys that are no setting at all, and how each is shown honoured.
	 *
	 * Derived by the compiler from the site rather than stored, so they have
	 * no schema leaf and nothing above would notice them going missing. Each
	 * names the test proving the library acts on it.
	 *
	 * @var array<string, string>
	 */
	private const DERIVED = array(
		'global.path_source'   => 'test_path_source',
		'global.base_path'     => 'test_path_source',
		'challenge.submit_url' => 'test_path_source',
	);

	/**
	 * Every derived key has a test, and none has become a setting.
	 */
	public function test_every_derived_key_is_covered(): void {
		$leaves = array();

		self::schema_leaves( Schema::definition(), '', $leaves );

		foreach ( self::DERIVED as $key => $how ) {
			$this->assertNotContains( $key, $leaves, "$key is a setting now; move it to COVERAGE." );
			$this->assertTrue( method_exists( $this, $how ), "$key names $how, which does not exist." );
		}
	}

	/**
	 * Every setting in the schema has an entry, and every entry a setting.
	 */
	public function test_every_setting_is_covered(): void {
		$leaves = array();

		self::schema_leaves( Schema::definition(), '', $leaves );

		$this->assertSame( array(), array_values( array_diff( $leaves, array_keys( self::COVERAGE ) ) ), 'These settings can be saved and nothing here says whether the library honours them.' );
		$this->assertSame( array(), array_values( array_diff( array_keys( self::COVERAGE ), $leaves ) ), 'These entries name settings the schema no longer has.' );

		foreach ( self::COVERAGE as $setting => $how ) {
			if ( 1 === preg_match( '/^(plugin|unapplied): /', $how ) ) {
				continue;
			}

			$this->assertTrue( method_exists( $this, $how ), "$setting names $how, which does not exist." );
		}
	}

	/**
	 * A firewall switched off evaluates nothing, whoever reads the file.
	 *
	 * The runner checks the setting before it calls the library; the
	 * wp-config.php path cannot, so the compiled file and its runtime sidecar
	 * have to carry it. EarlyPathExceptionModeTest drives that path.
	 */
	public function test_enabled(): void {
		$sidecar = \Kanopi\BasicFirewall\Plugin::instance()->paths()->runtime_file();

		$firewall = $this->build(
			array(
				'enabled' => false,
				'global'  => array(
					'mode'       => 'block',
					'panic_file' => $this->scratch . '/panic',
				),
			)
		);

		$this->assertSame( 'disabled', $firewall->getConfiguredMode()->value, 'A firewall switched off compiled to a mode that evaluates.' );
		$this->assertArrayNotHasKey( 'panic_file', $this->compiled['global'], 'A panic file could switch a disabled firewall back on.' );
		$this->assertFileExists( $sidecar );
		$this->assertSame( array( 'enabled' => false ), array_intersect_key( (array) json_decode( (string) file_get_contents( $sidecar ), true ), array( 'enabled' => true ) ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file.

		$firewall = $this->build( array( 'global' => array( 'mode' => 'block' ) ) );

		$this->assertSame( 'block', $firewall->getConfiguredMode()->value );
		$this->assertFileDoesNotExist( $sidecar, 'A sidecar holding only defaults was left for the early path to read on every request.' );
	}

	/**
	 * A member of an exempt role goes unevaluated; nobody else does.
	 *
	 * The runner's decision, asked directly: this process has already been
	 * marked evaluated, as every test run is. Where a login cookie is
	 * evaluated before the runner can check it is EarlyPathExceptionModeTest.
	 */
	public function test_bypass_roles(): void {
		require_once ABSPATH . 'wp-admin/includes/user.php';

		$editor     = wp_insert_user(
			array(
				'user_login' => 'bfw-bypass-editor-' . wp_generate_password( 6, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => 'editor',
			)
		);
		$subscriber = wp_insert_user(
			array(
				'user_login' => 'bfw-bypass-subscriber-' . wp_generate_password( 6, false ),
				'user_pass'  => wp_generate_password(),
				'role'       => 'subscriber',
			)
		);
		$cookies    = $_COOKIE;
		$method     = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : null;
		$runner     = \Kanopi\BasicFirewall\Plugin::instance()->runner();

		// wp_validate_auth_cookie() reads it, and a CLI run has none.
		$_SERVER['REQUEST_METHOD'] = 'GET';

		$this->assertIsInt( $editor );
		$this->assertIsInt( $subscriber );

		try {
			$this->build( array( 'global' => array( 'bypass_roles' => array( 'editor' ) ) ) );

			$sidecar = (array) json_decode( (string) file_get_contents( \Kanopi\BasicFirewall\Plugin::instance()->paths()->runtime_file() ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a local file.

			$this->assertTrue( $sidecar['defer_login'] ?? false, 'The wp-config.php path cannot tell that a login cookie has to wait for the runner.' );

			$as = static function ( $cookie ) {
				$_COOKIE = null === $cookie ? array() : array( LOGGED_IN_COOKIE => $cookie );

				return $_COOKIE;
			};

			$this->assertSame( 'exempt', self::invoke( $runner, 'bypass_decision', $as( wp_generate_auth_cookie( $editor, time() + 600, 'logged_in' ) ) ), 'A member of an exempt role was evaluated.' );
			$this->assertSame( 'evaluate', self::invoke( $runner, 'bypass_decision', $as( wp_generate_auth_cookie( $subscriber, time() + 600, 'logged_in' ) ) ), 'A member of a role that is not exempt went unevaluated.' );
			$this->assertSame( 'evaluate', self::invoke( $runner, 'bypass_decision', $as( 'bfw-bypass-editor|' . ( time() + 600 ) . '|forged|forged' ) ), 'A forged login cookie was exempted.' );
			$this->assertSame( 'evaluate', self::invoke( $runner, 'bypass_decision', $as( null ) ) );

			$this->build( array( 'global' => array( 'bypass_roles' => array() ) ) );

			$this->assertSame( 'evaluate', self::invoke( $runner, 'bypass_decision', $as( wp_generate_auth_cookie( $editor, time() + 600, 'logged_in' ) ) ), 'With no role exempt, an editor went unevaluated.' );
			$this->assertFileDoesNotExist( \Kanopi\BasicFirewall\Plugin::instance()->paths()->runtime_file() );
		} finally {
			$_COOKIE = $cookies;

			if ( null === $method ) {
				unset( $_SERVER['REQUEST_METHOD'] );
			} else {
				$_SERVER['REQUEST_METHOD'] = $method;
			}

			wp_delete_user( $editor );
			wp_delete_user( $subscriber );
		}
	}

	/**
	 * The mode the library runs in is the one chosen.
	 */
	public function test_mode(): void {
		foreach ( array( 'exception', 'log', 'block', 'disabled' ) as $mode ) {
			$firewall = $this->build( array( 'global' => array( 'mode' => $mode ) ) );

			$this->assertSame( $mode, $firewall->getConfiguredMode()->value );
		}
	}

	/**
	 * A panic file naming a mode switches to it.
	 */
	public function test_panic_file(): void {
		$file = $this->scratch . '/panic';

		file_put_contents( $file, "log\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions -- a scratch file.

		$firewall = $this->build( array( 'global' => array( 'panic_file' => $file ) ) );

		$this->assertTrue( $firewall->getPanicSwitch()['active'] );
		$this->assertSame( 'log', $firewall->getMode()->value );
	}

	/**
	 * Lockdown serves the allowlist, ranges included, and nobody else.
	 */
	public function test_lockdown(): void {
		$firewall = $this->build(
			array(
				'global' => array(
					'lockdown'       => true,
					'lockdown_allow' => array( '192.0.2.10-192.0.2.20', '198.51.100.0/24' ),
				),
			)
		);

		$this->assertTrue( $firewall->isLockedDown() );
		$this->assertSame( 'allow', $this->outcome( $firewall, self::request( '/', '192.0.2.15' ) )['verdict'], 'An address inside an allowlisted range was refused.' );
		$this->assertSame( 'allow', $this->outcome( $firewall, self::request( '/', '198.51.100.9' ) )['verdict'] );
		$this->assertSame( 'lockdown', $this->outcome( $firewall, self::request( '/', '192.0.2.21' ) )['verdict'] );
		$this->assertSame( array(), preg_grep( '/range/', $this->problems ), 'A range on the allowlist was reported as unsupported.' );
	}

	/**
	 * The site-wide status and message, and a rule's own status over them.
	 */
	public function test_banning_response(): void {
		$firewall = $this->build(
			array(
				'global' => array(
					'banning_status_code' => 451,
					'banning_message'     => 'Refused {{request.id}}',
				),
				'rules'  => array(
					$this->rule( 'site-code', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse-site' ) ) ) ),
					$this->rule( 'own-code', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse-own' ) ) ), array( 'status_code' => 410 ) ),
				),
			)
		);

		$site = $this->outcome( $firewall, self::request( '/refuse-site', '203.0.113.21' ) );
		$own  = $this->outcome( $firewall, self::request( '/refuse-own', '203.0.113.22' ) );

		$this->assertSame( 451, $site['status'] );
		$this->assertMatchesRegularExpression( '/^Refused [0-9A-Fa-f]+/', $site['message'] );
		$this->assertSame( 410, $own['status'] );
	}

	/**
	 * A block page, in the shared appearance, instead of one line of text.
	 *
	 * The page's message is the banning message, so a site switching the page
	 * on keeps the wording it already had.
	 */
	public function test_block_page(): void {
		$rules = array(
			$this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ) ),
		);

		$plain = $this->outcome(
			$this->build(
				array(
					'global' => array( 'banning_message' => 'Refused {{request.id}}' ),
					'rules'  => $rules,
				)
			),
			self::request( '/refuse', '203.0.113.31' )
		);

		$this->assertStringStartsWith( 'Refused ', $plain['message'], 'With the page off, the refusal is no longer the plain-text message.' );

		$firewall = $this->build(
			array(
				'global' => array(
					'banning_message' => "Refused.\nReference {{request.id}}",
					'block_page'      => array(
						'enabled' => true,
						'title'   => 'Honoured title',
						'heading' => 'Honoured heading',
					),
					'pages'           => array(
						'lang'       => 'fr-CA',
						'styles'     => ':root { --fw-accent: #0b8f5a; }',
						'stylesheet' => '/honoured/firewall.css',
					),
				),
				'rules'  => $rules,
			)
		);

		try {
			$firewall->evaluate( self::request( '/refuse', '203.0.113.32' ) );
			$this->fail( 'The rule did not block.' );
		} catch ( FirewallBlockedException $e ) {
			$page = $e->getMessage();

			$this->assertStringStartsWith( 'text/html', $e->getContentType() );
			$this->assertStringContainsString( '<html lang="fr-CA">', $page );
			$this->assertStringContainsString( '<title>Honoured title</title>', $page );
			$this->assertStringContainsString( 'Honoured heading', $page );
			$this->assertMatchesRegularExpression( '#<p>Refused\.</p>\s*<p>Reference [0-9A-Fa-f]+</p>#', $page, 'The banning message is not the page\'s text, a paragraph per line.' );
			$this->assertStringContainsString( '--fw-accent: #0b8f5a;', $page );
			$this->assertStringContainsString( 'href="/honoured/firewall.css"', $page );
		}

		/*
		 * A value the library would refuse to start on, stored without the
		 * screen's validation, costs that value and not the firewall.
		 */
		$firewall = $this->build(
			array(
				'global' => array(
					'block_page' => array( 'enabled' => true ),
					'pages'      => array(
						'lang'       => 'not a language',
						'styles'     => '</style><script>alert(1)</script>',
						'stylesheet' => 'javascript:alert(1)',
					),
				),
				'rules'  => $rules,
			),
			true
		);

		$this->assertTrue( self::property( $firewall, 'config' )['block_page'] ?? null, 'Unusable page values were written into the compiled file.' );
		$this->assertSame( 'block', $this->outcome( $firewall, self::request( '/refuse', '203.0.113.33' ) )['verdict'] );

		// And the screen's save refuses each of them, in the library's words.
		$problems = Plugin::instance()->settings()->replace(
			self::merge(
				Plugin::instance()->settings()->all(),
				array(
					'global' => array(
						'pages' => array(
							'lang'       => 'not a language',
							'styles'     => '</style>',
							'stylesheet' => '//elsewhere.example/x.css',
						),
					),
				)
			)
		);

		$this->assertSame(
			array( 'global.pages.lang', 'global.pages.styles', 'global.pages.stylesheet' ),
			array_column( $problems, 'path' )
		);
		$this->assertSame( '', Plugin::instance()->settings()->get( 'global.pages.stylesheet' ) );
	}

	/**
	 * A lockdown page, with its own message.
	 */
	public function test_lockdown_page(): void {
		$firewall = $this->build(
			array(
				'global' => array(
					'lockdown'       => true,
					'lockdown_allow' => array( '198.51.100.0/24' ),
					'lockdown_page'  => array(
						'enabled' => true,
						'title'   => 'Back soon',
						'heading' => 'Closed for maintenance',
						'message' => "Back at 18:00 UTC.\nReference {{request.id}}",
					),
				),
			)
		);

		try {
			$firewall->evaluate( self::request( '/', '192.0.2.40' ) );
			$this->fail( 'Lockdown let an address off the allowlist through.' );
		} catch ( FirewallLockdownException $e ) {
			$page = $e->getMessage();

			$this->assertStringStartsWith( 'text/html', $e->getContentType() );
			$this->assertStringContainsString( '<title>Back soon</title>', $page );
			$this->assertStringContainsString( 'Closed for maintenance', $page );
			$this->assertMatchesRegularExpression( '#<p>Back at 18:00 UTC\.</p>\s*<p>Reference [0-9A-Fa-f]+</p>#', $page );
		}
	}

	/**
	 * A client that asks for JSON first gets JSON; a browser does not.
	 */
	public function test_banning_json(): void {
		$firewall = $this->build(
			array(
				'global' => array(
					'banning_json' => true,
					'block_page'   => array( 'enabled' => true ),
				),
				'rules'  => array(
					$this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ) ),
				),
			)
		);

		foreach ( array(
			'203.0.113.34' => array( 'application/json', 'application/json' ),
			'203.0.113.36' => array( 'text/html,application/xhtml+xml', 'text/html' ),
		) as $ip => list( $accept, $expected ) ) {
			try {
				$firewall->evaluate( self::request( '/refuse', $ip, array( 'Accept' => $accept ) ) );
				$this->fail( 'The rule did not block.' );
			} catch ( FirewallBlockedException $e ) {
				$this->assertStringStartsWith( $expected, $e->getContentType(), "Accept: $accept" );
			}
		}

		$this->assertSame( 'blocked', json_decode( $this->outcome( $firewall, self::request( '/refuse', '203.0.113.35', array( 'Accept' => 'application/json' ) ) )['message'], true )['error'] ?? null );
	}

	/**
	 * A returning blocked client gets the repeat status, and a longer block.
	 */
	public function test_repeat_offenders(): void {
		$firewall = $this->build(
			array(
				'global' => array(
					'repeat_offender_status' => 429,
					'add_to_expire'          => 900,
				),
				'rules'  => array(
					$this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ), array( 'expiration' => 600 ) ),
				),
			)
		);

		$this->assertSame( 'block', $this->outcome( $firewall, self::request( '/refuse', '203.0.113.31' ) )['verdict'] );

		$storage = self::property( $firewall, 'storage' );
		$key     = $storage->getKey( self::request( '/', '203.0.113.31' ) );
		$before  = (int) ( self::property( $storage, 'store' )[ $key ]['expire'] ?? 0 );

		$this->assertGreaterThan( time(), $before, 'The block was not recorded with an expiry.' );

		$again = $this->outcome( $firewall, self::request( '/anything', '203.0.113.31' ) );

		$this->assertSame( 429, $again['status'] );
		$this->assertSame( $before + 900, (int) ( self::property( $storage, 'store' )[ $key ]['expire'] ?? 0 ), 'The block was not extended by what was configured.' );
	}

	/**
	 * The smallest extension the form offers is one the library applies.
	 *
	 * The library drops a zero from its global section before reading it and
	 * then adds its own 3600, so "nothing added" cannot be expressed.
	 */
	public function test_add_to_expire_cannot_claim_zero(): void {
		$node = Schema::definition()['children']['global']['children']['add_to_expire'];

		$this->assertGreaterThanOrEqual( 1, (int) ( $node['min'] ?? 0 ), 'The form offers 0, which the library reads as 3600.' );
	}

	/**
	 * The proxy posture is asserted, and escalated when required.
	 */
	public function test_proxy_posture(): void {
		Request::setTrustedProxies( array(), Request::getTrustedHeaderSet() );

		foreach ( array(
			'yes'     => true,
			'unknown' => true,
			'no'      => false,
		) as $behind => $refuses ) {
			$this->given_settings(
				self::merge(
					$this->base_settings(),
					array(
						'global' => array(
							'behind_proxy'            => $behind,
							'require_trusted_proxies' => true,
						),
					)
				)
			);

			\Kanopi\BasicFirewall\Plugin::instance()->compiled()->rebuild();

			$refused = false;

			try {
				Firewall::create( array( \Kanopi\BasicFirewall\Plugin::instance()->paths()->compiled_file() ) );
			} catch ( ConfigurationException $e ) {
				$refused = true;
			}

			$this->assertSame( $refuses, $refused, "Behind a proxy: $behind, with trusted proxies required and none configured." );
		}
	}

	/**
	 * Whether a configuration that failed to load stops the library starting.
	 */
	public function test_require_config(): void {
		foreach ( array( true, false ) as $required ) {
			$this->build( array( 'global' => array( 'require_config' => $required ) ) );

			$this->assertSame( $required, self::invoke( Firewall::class, 'requireConfig', (array) $this->compiled['global'] ) );
		}
	}

	/**
	 * `path_source: script_name` and `base_path`, compiled for each layout and honoured.
	 *
	 * Neither is a setting: the compiler always writes the one and derives the
	 * other from the site's addresses (see Site_Layout). The requests are the
	 * server values a web server sends, so the path is the one the library
	 * resolves in production.
	 */
	public function test_path_source(): void {
		$rules = array(
			$this->rule( 'root-login', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/wp-login.php' ) ) ), array( 'expiration' => 1 ) ),
			$this->rule( 'own-login', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/wp/wp-login.php' ) ) ), array( 'expiration' => 1 ) ),
			// Only so the challenge section, and its submit URL, is compiled.
			$this->rule( 'never', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/never-requested' ) ) ), array( 'response' => 'challenge' ) ),
		);

		$challenge = (string) \Kanopi\BasicFirewall\Plugin::instance()->settings()->get( 'challenge.path', '/basic-firewall/challenge' );

		// At the web root: no base path, and wp-login.php is itself.
		$firewall = $this->build( array( 'rules' => $rules ) );

		$this->assertSame( RequestPath::SCRIPT_NAME, $this->compiled['global']['path_source'] ?? null );
		$this->assertArrayNotHasKey( 'base_path', (array) $this->compiled['global'] );
		$this->assertSame( $challenge, $this->compiled['challenge']['submit_url'] ?? null );
		$this->assertSame( array( 'block', '/wp-login.php' ), $this->resolved( $firewall, '/wp-login.php', '/wp-login.php', '203.0.113.90' ) );
		$this->assertSame( array( 'allow', '/wp-admin/edit.php' ), $this->resolved( $firewall, '/wp-admin/edit.php?post_type=page', '/wp-admin/edit.php', '203.0.113.91' ) );
		$this->assertSame( array( 'allow', '/sample-page/' ), $this->resolved( $firewall, '/sample-page/', '/index.php', '203.0.113.92' ) );

		/*
		 * The subdirectory layouts below are single-site ones: a network
		 * takes its base path from the network's own path, which filtering
		 * home cannot move. SiteLayoutTest covers network layouts.
		 */
		if ( is_multisite() ) {
			return;
		}

		$addresses = array(
			'home'    => 'http://example.org/blog',
			'siteurl' => 'http://example.org/blog',
		);

		$filter = static function ( $value, string $option ) use ( &$addresses ) {
			return $addresses[ $option ] ?? $value;
		};

		add_filter( 'pre_option_home', $filter, 10, 2 );
		add_filter( 'pre_option_siteurl', $filter, 10, 2 );

		try {
			// In a subdirectory: the base path comes off, pages route through /blog/index.php.
			$firewall = $this->build( array( 'rules' => $rules ) );

			$this->assertSame( '/blog', $this->compiled['global']['base_path'] ?? null );
			$this->assertSame( '/blog' . $challenge, $this->compiled['challenge']['submit_url'] ?? null );
			$this->assertSame( array( 'block', '/wp-login.php' ), $this->resolved( $firewall, '/blog/wp-login.php', '/blog/wp-login.php', '203.0.113.93' ) );
			$this->assertSame( array( 'allow', '/sample-page/' ), $this->resolved( $firewall, '/blog/sample-page/', '/blog/index.php', '203.0.113.94' ) );

			// WordPress in its own directory: index.php is at the root, so no
			// base path, and the core files keep their directory.
			$addresses = array(
				'home'    => 'http://example.org',
				'siteurl' => 'http://example.org/wp',
			);

			$firewall = $this->build( array( 'rules' => $rules ) );

			$this->assertArrayNotHasKey( 'base_path', (array) $this->compiled['global'] );
			$this->assertSame( $challenge, $this->compiled['challenge']['submit_url'] ?? null );
			$this->assertSame( array( 'block', '/wp/wp-login.php' ), $this->resolved( $firewall, '/wp/wp-login.php', '/wp/wp-login.php', '203.0.113.95' ) );
			// The bare address is no file here: the server routes it through
			// index.php, where it is matched as typed and WordPress redirects it.
			$this->assertSame( array( 'block', '/wp-login.php' ), $this->resolved( $firewall, '/wp-login.php', '/index.php', '203.0.113.96' ) );
			$this->assertSame( array( 'allow', '/sample-page/' ), $this->resolved( $firewall, '/sample-page/', '/index.php', '203.0.113.97' ) );
		} finally {
			remove_filter( 'pre_option_home', $filter, 10 );
			remove_filter( 'pre_option_siteurl', $filter, 10 );
		}
	}

	/**
	 * The verdict on a request as a web server describes it, and the path the rules saw.
	 *
	 * @param Firewall $firewall The firewall.
	 * @param string   $uri      REQUEST_URI.
	 * @param string   $script   SCRIPT_NAME: the file the server ran.
	 * @param string   $ip       Client address.
	 *
	 * @return array{0: string, 1: string}
	 */
	private function resolved( Firewall $firewall, string $uri, string $script, string $ip ): array {
		$request = self::served( $uri, $script, $ip );
		$verdict = $this->outcome( $firewall, $request )['verdict'];

		return array( $verdict, RequestPath::of( $request ) );
	}

	/**
	 * A request carrying the server values a web server sends.
	 *
	 * @param string $uri    REQUEST_URI.
	 * @param string $script SCRIPT_NAME.
	 * @param string $ip     Client address.
	 */
	private static function served( string $uri, string $script, string $ip ): Request {
		$query = wp_parse_url( $uri, PHP_URL_QUERY );

		$request = new Request(
			array(),
			array(),
			array(),
			array(),
			array(),
			array(
				'REQUEST_METHOD'  => 'GET',
				'REQUEST_URI'     => $uri,
				'QUERY_STRING'    => is_string( $query ) ? $query : '',
				'SCRIPT_NAME'     => $script,
				'PHP_SELF'        => $script,
				'SCRIPT_FILENAME' => ABSPATH . ltrim( $script, '/' ),
				'HTTP_HOST'       => 'example.org',
				'REMOTE_ADDR'     => $ip,
				'HTTP_USER_AGENT' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
			)
		);

		return $request;
	}

	/**
	 * A rule's own duration, and an escalation stage over it.
	 */
	public function test_blocking_escalation(): void {
		$rule = $this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ), array( 'expiration' => 600 ) );

		$firewall = $this->build( array( 'rules' => array( $rule ) ) );

		$this->assertSame( 600, $this->plugin_named( $firewall, 'refuse' )->getExpirationTime() );
		$this->assertSame( 600, self::invoke( $firewall, 'determineExpirationTime', self::request( '/', '203.0.113.41' ), 600 ) );

		$firewall = $this->build(
			array(
				'global' => array(
					'blocking_escalation' => array(
						array(
							'window'             => 3600,
							'offense'            => 0,
							'duration'           => 7200,
							'use_plugin_default' => false,
						),
					),
				),
				'rules'  => array( $rule ),
			)
		);

		$this->assertSame( 7200, self::invoke( $firewall, 'determineExpirationTime', self::request( '/', '203.0.113.42' ), 600 ), 'The escalation stage was not applied.' );

		$firewall = $this->build(
			array(
				'global' => array(
					'blocking_escalation' => array(
						array(
							'window'             => 3600,
							'offense'            => 0,
							'duration'           => 7200,
							'use_plugin_default' => true,
						),
					),
				),
				'rules'  => array( $rule ),
			)
		);

		$this->assertSame( 600, self::invoke( $firewall, 'determineExpirationTime', self::request( '/', '203.0.113.43' ), 600 ), 'A stage using the rule\'s own duration did not.' );
	}

	/**
	 * Agent detection caches where the Storage screen says.
	 */
	public function test_cache_backend(): void {
		$rule = $this->rule(
			'agents',
			'user_agent',
			array(
				'conditions'      => array( self::condition( 'bot', 'equals', 'true' ) ),
				'cache_detection' => true,
			)
		);

		$firewall = $this->build(
			array(
				'cache' => array(
					'backend'   => 'filesystem',
					'directory' => $this->scratch . '/cache',
				),
				'rules' => array( $rule ),
			)
		);

		$plugin = $this->plugin_named( $firewall, 'agents' );
		$pool   = self::invoke( $plugin, 'cachePool', self::property( $plugin, 'metadata' )['cache'] ?? null );

		$this->assertInstanceOf( FilesystemAdapter::class, $pool );
		$this->assertStringStartsWith( $this->scratch . '/cache', (string) self::property( $pool, 'directory' ) );
	}

	/**
	 * APCu, with its lifetime, where the extension is usable.
	 */
	public function test_apcu_cache(): void {
		$firewall = $this->build(
			array(
				'cache' => array(
					'backend'  => 'apcu',
					'apcu_ttl' => 1234,
				),
				'rules' => array(
					$this->rule(
						'agents',
						'user_agent',
						array(
							'conditions'      => array( self::condition( 'bot', 'equals', 'true' ) ),
							'cache_detection' => true,
						)
					),
				),
			)
		);

		$declared = self::property( $this->plugin_named( $firewall, 'agents' ), 'metadata' )['cache'] ?? null;

		$this->assertSame( ApcuAdapter::class, $declared['adaptor'] ?? null );
		$this->assertSame( 1234, $declared['args'][1] ?? null );

		if ( ! ApcuAdapter::isSupported() ) {
			$this->markTestIncomplete( 'APCu is not usable from this PHP, so the pool could not be built to read its lifetime back.' );
		}

		$pool = self::invoke( $this->plugin_named( $firewall, 'agents' ), 'cachePool', $declared );

		$this->assertInstanceOf( ApcuAdapter::class, $pool );
		$this->assertSame( 1234, self::property( $pool, 'defaultLifetime' ) );
	}

	/**
	 * Block records go to the files named, and a block writes one.
	 */
	public function test_file_storage(): void {
		$firewall = $this->build(
			array(
				'storage' => array(
					'backend' => 'file',
					'file'    => array(
						'storage_file' => $this->scratch . '/named.data',
						'offense_file' => $this->scratch . '/named.offenses',
					),
				),
				'rules'   => array( $this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ) ) ),
			)
		);

		$storage = self::property( $firewall, 'storage' );

		$this->assertInstanceOf( FileStorage::class, $storage );
		$this->assertSame( $this->scratch . '/named.data', self::property( $storage, 'filePath' ) );
		$this->assertSame( $this->scratch . '/named.offenses', self::property( $storage, 'offensesFilePath' ) );

		$this->outcome( $firewall, self::request( '/refuse', '203.0.113.51' ) );

		$this->assertFileExists( $this->scratch . '/named.data' );
	}

	/**
	 * Database storage, from WordPress's connection, from parameters and from a DSN.
	 */
	public function test_database_storage(): void {
		global $wpdb;

		$credentials = new Database_Credentials();
		$parameters  = $credentials->get_connection_parameters();
		$suffix      = bin2hex( random_bytes( 3 ) );
		$created     = array();

		$sources = array(
			'wordpress'  => array(),
			'parameters' => array(
				'parameters' => array(
					'driver'   => (string) $parameters['driver'],
					'host'     => (string) ( $parameters['host'] ?? 'localhost' ),
					'port'     => (int) ( $parameters['port'] ?? 3306 ),
					'dbname'   => (string) $parameters['dbname'],
					'user'     => (string) $parameters['user'],
					'password' => (string) $parameters['password'],
				),
			),
			'dsn'        => array(
				'dsn' => sprintf(
					'pdo-mysql://%s:%s@%s:%d/%s',
					rawurlencode( (string) $parameters['user'] ),
					rawurlencode( (string) $parameters['password'] ),
					(string) ( $parameters['host'] ?? 'localhost' ),
					(int) ( $parameters['port'] ?? 3306 ),
					rawurlencode( (string) $parameters['dbname'] )
				),
			),
		);

		try {
			foreach ( $sources as $source => $connection ) {
				$blocked  = "bfw_honoured_blocked_{$source}_{$suffix}";
				$offenses = "bfw_honoured_offenses_{$source}_{$suffix}";
				$expected = 'wordpress' === $source ? array( $credentials->prefix_table( $blocked ), $credentials->prefix_table( $offenses ) ) : array( $blocked, $offenses );

				$created = array_merge( $created, $expected );

				$firewall = $this->build(
					array(
						'storage' => array(
							'backend'  => 'database',
							'database' => array(
								'connection_source' => $source,
								'storage_table'     => $blocked,
								'offenses_table'    => $offenses,
							) + $connection,
						),
						'rules'   => array( $this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ) ) ),
					)
				);

				$storage = self::property( $firewall, 'storage' );

				$this->assertInstanceOf( DatabaseStorage::class, $storage, "Database storage from $source fell back to something else: " . implode( ' ', $this->problems ) );
				$this->assertSame( $expected[0], self::property( $storage, 'config' )['storage_table'] ?? null );
				$this->assertSame( $expected[1], self::property( $storage, 'config' )['offenses_table'] ?? null );

				$this->outcome( $firewall, self::request( '/refuse', '203.0.113.52' ) );

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- a table this test created.
				$this->assertSame( '1', (string) $wpdb->get_var( "SELECT COUNT(*) FROM `{$expected[0]}`" ), "No block was written through the $source connection." );
			}
		} finally {
			foreach ( $created as $table ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test cleanup.
				$wpdb->query( "DROP TABLE IF EXISTS `$table`" );
			}
		}
	}

	/**
	 * Redis storage connects with what was typed.
	 */
	public function test_redis_storage(): void {
		if ( ! extension_loaded( 'redis' ) ) {
			$this->markTestSkipped( 'The redis extension is not loaded, so the plugin compiles file storage instead.' );
		}

		$firewall = $this->build(
			array(
				'storage' => array(
					'backend' => 'redis',
					'redis'   => array(
						'host'     => '192.0.2.61',
						'port'     => 6390,
						'prefix'   => 'honoured:',
						'username' => 'firewall',
						'password' => 'hunter2',
					),
				),
			)
		);

		$storage = self::property( $firewall, 'storage' );

		$this->assertInstanceOf( RedisStorage::class, $storage );

		$options = self::property( $storage, 'config' )['redis'] ?? array();

		$this->assertSame( '192.0.2.61', $options['host'] ?? null );
		$this->assertSame( 6390, $options['port'] ?? null );
		$this->assertSame( 'honoured:', $options['prefix'] ?? null );
		$this->assertSame( array( 'firewall', 'hunter2' ), $options['auth'] ?? null );
	}

	/**
	 * A block record keeps what the allowlists say, and nothing else.
	 */
	public function test_record_request(): void {
		$firewall = $this->build(
			array(
				'storage' => array(
					'record_request' => array(
						'cookies' => 'keep_cookie',
						'headers' => "X-Keep\nUser-Agent",
						'query'   => 'keep',
						'body'    => '',
					),
				),
				'rules'   => array( $this->rule( 'refuse', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/refuse' ) ) ) ) ),
			)
		);

		$request = Request::create(
			'/refuse?keep=1&drop=2',
			'POST',
			array( 'field' => 'secret' ),
			array(
				'keep_cookie' => 'a',
				'session'     => 'b',
			),
			array(),
			array( 'REMOTE_ADDR' => '203.0.113.53' )
		);

		$request->headers->set( 'X-Keep', 'yes' );
		$request->headers->set( 'X-Drop', 'no' );

		$this->outcome( $firewall, $request );

		$storage = self::property( $firewall, 'storage' );
		$record  = (string) wp_json_encode( $storage->get( $storage->getKey( $request ) ) );

		$this->assertStringContainsString( 'keep_cookie', $record );
		$this->assertStringNotContainsString( 'session', $record );
		$this->assertStringContainsString( 'x-keep', strtolower( $record ) );
		$this->assertStringNotContainsString( 'x-drop', strtolower( $record ) );
		$this->assertStringNotContainsString( 'drop=2', $record );
		$this->assertStringNotContainsString( '"drop"', $record );
		$this->assertStringNotContainsString( 'secret', $record );
	}

	/**
	 * The signing section, and a rule sending visitors to another provider.
	 *
	 * ALTCHA's widget settings only apply when they reach the provider, and a
	 * rule that overrides the default provider gets options only when they are
	 * keyed by that provider's name.
	 */
	public function test_challenge_section(): void {
		$firewall = $this->build(
			array(
				'challenge' => array(
					'provider'         => 'math',
					'secret'           => str_repeat( 'k', 48 ),
					'ttl'              => 1800,
					'path'             => '/honoured/challenge',
					'cookie_name'      => 'honoured_pass',
					'header_name'      => 'X-Honoured-Pass',
					'audience'         => 'honoured-site',
					'provider_options' => array(
						'altcha' => array(
							'widget_src'       => '/assets/altcha.min.js',
							'widget_integrity' => 'sha384-honoured',
						),
					),
				),
				'rules'     => array(
					$this->rule( 'puzzle', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/puzzle' ) ) ), array( 'response' => 'challenge' ) ),
					$this->rule(
						'work',
						'url',
						array( 'conditions' => array( self::condition( 'path', 'equals', '/work' ) ) ),
						array(
							'response'           => 'challenge',
							'challenge_provider' => 'altcha',
						)
					),
				),
			)
		);

		$config = self::property( $firewall, 'challengeConfig' );

		$this->assertSame( '/honoured/challenge', $config['path'] );
		$this->assertSame( 'honoured_pass', $config['cookie_name'] );
		$this->assertSame( 'X-Honoured-Pass', $config['header_name'] );
		$this->assertSame( 1800, $config['ttl'] );

		$tokens = self::property( $firewall, 'tokenManager' );

		$this->assertSame( 'honoured-site', self::property( $tokens, 'audience' ) );

		if ( ! Challenge_Secret::is_overridden() ) {
			$this->assertSame( str_repeat( 'k', 48 ), self::property( $tokens, 'secret' ) );
		}

		$registry = self::property( $firewall, 'challengeProviderRegistry' );

		$this->assertSame( 'altcha', $this->plugin_named( $firewall, 'work' )->getChallengeProviderName() );

		$altcha = $registry->get( 'altcha' );

		$this->assertSame( '/assets/altcha.min.js', self::property( $altcha, 'widgetSrc' ) );
		$this->assertSame( 'sha384-honoured', self::property( $altcha, 'widgetIntegrity' ) );

		$this->assertSame( 'challenge', $this->outcome( $firewall, self::request( '/puzzle', '203.0.113.81' ) )['verdict'] );
	}

	/**
	 * The interstitial's wording, and the shared appearance, on the page.
	 */
	public function test_challenge_page(): void {
		$firewall = $this->build(
			array(
				'global'    => array(
					'pages' => array(
						'lang'   => 'fr',
						'styles' => '.card { border-top: 4px solid #0b5; }',
					),
				),
				'challenge' => array(
					'provider' => 'math',
					'page'     => array(
						'title'         => 'Vérification requise',
						'heading'       => 'Vérification rapide',
						'intro'         => 'Merci de confirmer que vous êtes humain.',
						'button'        => 'Continuer',
						'error_message' => 'La vérification a échoué.',
						'styles'        => ':root { --fw-accent: #0b8f5a; }',
						'stylesheet'    => '/honoured/challenge.css',
					),
					'notice'   => array( 'Besoin d\'aide ? help@example.com', '  ' ),
				),
				'rules'     => array(
					$this->rule( 'puzzle', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/puzzle' ) ) ), array( 'response' => 'challenge' ) ),
				),
			)
		);

		// Equal, not identical: the library orders the keys its own way.
		$this->assertEquals(
			array(
				'title'         => 'Vérification requise',
				'heading'       => 'Vérification rapide',
				'intro'         => 'Merci de confirmer que vous êtes humain.',
				'button'        => 'Continuer',
				'error_message' => 'La vérification a échoué.',
				'lang'          => 'fr',
				'styles'        => ".card { border-top: 4px solid #0b5; }\n:root { --fw-accent: #0b8f5a; }",
				'stylesheet'    => '/honoured/challenge.css',
			),
			self::property( $firewall, 'challengeConfig' )['page'] ?? null,
			'The shared CSS did not come first with the challenge page\'s own after it.'
		);

		$this->assertSame( array( 'Besoin d\'aide ? help@example.com' ), self::property( $firewall, 'challengeConfig' )['notice'] ?? null );

		$request = self::request( '/puzzle', '203.0.113.82' );

		try {
			$firewall->evaluate( $request );
			$this->fail( 'The rule did not challenge.' );
		} catch ( ChallengeRequiredException $e ) {
			$page = $e->renderInterstitial( $request );

			$this->assertStringContainsString( '<html lang="fr">', $page );
			$this->assertStringContainsString( 'Vérification rapide', $page );
			$this->assertStringContainsString( 'Continuer', $page );
			$this->assertStringContainsString( 'border-top: 4px solid #0b5;', $page );
			$this->assertStringContainsString( '--fw-accent: #0b8f5a;', $page );
			$this->assertStringContainsString( 'href="/honoured/challenge.css"', $page );
			$this->assertStringContainsString( 'Besoin d&#039;aide ? help@example.com', $page );
		}
	}

	/**
	 * Turnstile as the default and reCAPTCHA through a rule, both configured.
	 *
	 * The case that took the whole firewall down: the library builds every
	 * named provider at startup, and neither remote one constructs without its
	 * keys.
	 */
	public function test_remote_challenge_providers(): void {
		$firewall = $this->build(
			array(
				'challenge' => array(
					'provider'         => 'turnstile',
					'provider_options' => array(
						'turnstile' => array(
							'site_key'      => '1x00000000000000000000AA',
							'secret_key'    => '1x0000000000000000000000000000000AA',
							'theme'         => 'dark',
							'widget_src'    => '/assets/turnstile.js',
							'timeout'       => 8,
							'on_error'      => 'pass',
							'send_remoteip' => true,
						),
						'recaptcha' => array(
							'site_key'          => 'recaptcha-site',
							'secret_key'        => 'recaptcha-secret',
							'version'           => 'v3',
							'theme'             => 'dark',
							'size'              => 'compact',
							'min_score'         => 0.7,
							'action'            => 'honoured',
							'widget_src'        => '/assets/recaptcha.js',
							'timeout'           => 4,
							'on_error'          => 'fail',
							'send_remoteip'     => false,
							'use_recaptcha_net' => true,
						),
					),
				),
				'rules'     => array(
					$this->rule( 'default-provider', 'url', array( 'conditions' => array( self::condition( 'path', 'equals', '/turnstile' ) ) ), array( 'response' => 'challenge' ) ),
					$this->rule(
						'google',
						'url',
						array( 'conditions' => array( self::condition( 'path', 'equals', '/recaptcha' ) ) ),
						array(
							'response'           => 'challenge',
							'challenge_provider' => 'recaptcha',
						)
					),
				),
			)
		);

		$registry = self::property( $firewall, 'challengeProviderRegistry' );

		$this->assertSame( 'turnstile', $registry->getDefaultName() );

		$turnstile = $registry->get( 'turnstile' );

		$this->assertInstanceOf( TurnstileChallengeProvider::class, $turnstile );
		$this->assertSame( '1x00000000000000000000AA', self::property( $turnstile, 'siteKey' ) );
		$this->assertSame( '1x0000000000000000000000000000000AA', self::property( $turnstile, 'secretKey' ) );
		$this->assertSame( 'dark', self::property( $turnstile, 'theme' ) );
		$this->assertSame( '/assets/turnstile.js', self::property( $turnstile, 'widgetSrc' ) );
		$this->assertSame( 8, self::property( $turnstile, 'timeout' ) );
		$this->assertTrue( self::property( $turnstile, 'allowOnError' ), '"Let the visitor through" did not reach the provider.' );
		$this->assertTrue( self::property( $turnstile, 'sendRemoteIp' ) );

		$recaptcha = $registry->get( 'recaptcha' );

		$this->assertInstanceOf( RecaptchaChallengeProvider::class, $recaptcha );
		$this->assertSame( 'recaptcha-site', self::property( $recaptcha, 'siteKey' ) );
		$this->assertSame( 'recaptcha-secret', self::property( $recaptcha, 'secretKey' ) );
		$this->assertSame( 'v3', self::property( $recaptcha, 'version' ) );
		$this->assertSame( 'dark', self::property( $recaptcha, 'theme' ) );
		$this->assertSame( 'compact', self::property( $recaptcha, 'size' ) );
		$this->assertSame( 0.7, self::property( $recaptcha, 'minScore' ) );
		$this->assertSame( 'honoured', self::property( $recaptcha, 'action' ) );
		$this->assertStringStartsWith( '/assets/recaptcha.js', self::property( $recaptcha, 'widgetSrc' ) );
		$this->assertSame( 4, self::property( $recaptcha, 'timeout' ) );
		$this->assertFalse( self::property( $recaptcha, 'allowOnError' ) );
		$this->assertFalse( self::property( $recaptcha, 'sendRemoteIp' ) );
		$this->assertStringContainsString( 'recaptcha.net', self::property( $recaptcha, 'host' ) );
	}

	/**
	 * The timeout field offers nothing the library would quietly shorten.
	 */
	public function test_challenge_timeouts_fit_the_library(): void {
		$providers = Schema::definition()['children']['challenge']['children']['provider_options']['children'];

		foreach ( array(
			'turnstile' => TurnstileChallengeProvider::class,
			'recaptcha' => RecaptchaChallengeProvider::class,
		) as $name => $class ) {
			$ceiling = ( new \ReflectionClassConstant( $class, 'MAX_TIMEOUT' ) )->getValue();

			$this->assertLessThanOrEqual( $ceiling, $providers[ $name ]['children']['timeout']['max'], "The $name timeout offers more than the library allows." );
			$this->assertLessThanOrEqual( $ceiling, $providers[ $name ]['children']['timeout']['default'] );
		}
	}

	/**
	 * Additional names are redacted from the log on both paths, defaults kept.
	 */
	public function test_redact_extra(): void {
		$this->build(
			array(
				'logging' => array(
					'redact_extra' => array( ' Header.X-Honoured-Session ', 'query.*', '' ),
				),
			)
		);

		try {
			self::invoke( \Kanopi\BasicFirewall\Plugin::instance()->runner(), 'apply_redaction' );

			$this->assertTrue( LoggingFactory::shouldRedactVariable( 'header.x-honoured-session' ), 'A name typed on the Logging screen is logged in clear.' );
			$this->assertTrue( LoggingFactory::shouldRedactVariable( 'query.token' ), 'A prefix typed on the Logging screen is logged in clear.' );
			$this->assertTrue( LoggingFactory::shouldRedactVariable( 'header.cookie' ), 'Adding a name stopped the library redacting its own defaults.' );
			$this->assertFalse( LoggingFactory::shouldRedactVariable( 'header.user-agent' ) );

			// The wp-config.php path reads the same names from the sidecar.
			require_once dirname( __DIR__, 2 ) . '/bootstrap.php';

			$runtime = basic_firewall_runtime( array( 'private_path' => \Kanopi\BasicFirewall\Plugin::instance()->paths()->base() ) + basic_firewall_options() );

			$this->assertSame( array( 'header.x-honoured-session', 'query.*' ), $runtime['redact'], 'The wp-config.php path cannot see the names to redact.' );

			\Kanopi\BasicFirewall\Logging\Redaction::apply( array() );

			basic_firewall_apply_redaction( basic_firewall_options(), $runtime['redact'] );

			$this->assertTrue( LoggingFactory::shouldRedactVariable( 'header.x-honoured-session' ), 'The wp-config.php path did not hand the names to the library.' );
		} finally {
			\Kanopi\BasicFirewall\Logging\Redaction::apply( array() );
		}

		$this->assertFalse( LoggingFactory::shouldRedactVariable( 'header.x-honoured-session' ), 'Names from one configuration outlived it.' );
	}

	/**
	 * File, stream and error-log handlers, deferred and not, at their levels.
	 */
	public function test_log_handlers(): void {
		$this->build(
			array(
				'logger' => array(
					array(
						'type'      => 'rotating_file',
						'enabled'   => true,
						'level'     => 'error',
						'path'      => $this->scratch . '/rotating.log',
						'max_files' => 3,
					),
					array(
						'type'     => 'stream',
						'enabled'  => true,
						'level'    => 'notice',
						'path'     => $this->scratch . '/stream.log',
						'deferred' => true,
					),
					array(
						'type'    => 'error_log',
						'enabled' => true,
						'level'   => 'critical',
					),
					array(
						'type'    => 'stream',
						'enabled' => false,
						'path'    => $this->scratch . '/disabled.log',
					),
				),
			)
		);

		$handlers = LoggingFactory::logger()->getHandlers();
		$found    = array();

		foreach ( $handlers as $handler ) {
			$inner = $handler instanceof DeferredHandler ? self::property( $handler, 'handler' ) : $handler;

			$found[ get_class( $inner ) ][] = array(
				'handler'  => $inner,
				'deferred' => $handler instanceof DeferredHandler,
			);
		}

		$rotating = $found[ RotatingFileHandler::class ][0] ?? null;

		$this->assertNotNull( $rotating );
		$this->assertSame( 3, self::property( $rotating['handler'], 'maxFiles' ) );
		$this->assertSame( $this->scratch . '/rotating.log', self::property( $rotating['handler'], 'filename' ) );
		$this->assertSame( 'ERROR', $rotating['handler']->getLevel()->getName() );
		$this->assertFalse( $rotating['deferred'] );

		$streams = $found[ StreamHandler::class ] ?? array();

		$this->assertCount( 1, $streams, 'A disabled handler was built, or an enabled one was not.' );
		$this->assertSame( $this->scratch . '/stream.log', $streams[0]['handler']->getUrl() );
		$this->assertSame( 'NOTICE', $streams[0]['handler']->getLevel()->getName() );
		$this->assertTrue( $streams[0]['deferred'] );

		$this->assertSame( 'CRITICAL', ( $found[ ErrorLogHandler::class ][0]['handler'] ?? null )?->getLevel()->getName() );
	}

	/**
	 * The database handler's table, retention, buffering and connection.
	 */
	public function test_database_log_handler(): void {
		$credentials = new Database_Credentials();
		$parameters  = $credentials->get_connection_parameters();

		$this->build(
			array(
				'logger' => array(
					array(
						'type'              => 'database',
						'enabled'           => true,
						'level'             => 'warning',
						'table'             => 'honoured_log',
						'connection_source' => 'wordpress',
						'retain_days'       => 12,
						'prune_batch_size'  => 250,
						'prune_max_batches' => 4,
						'buffered'          => false,
					),
					array(
						'type'              => 'database',
						'enabled'           => true,
						'level'             => 'error',
						'table'             => 'honoured_dsn_log',
						'connection_source' => 'dsn',
						'dsn'               => 'pdo-mysql://user:pass@db.example:3306/logs',
						'retain_days'       => 5,
						'buffered'          => true,
					),
					array(
						'type'              => 'database',
						'enabled'           => true,
						'level'             => 'error',
						'table'             => 'honoured_parameters_log',
						'connection_source' => 'parameters',
						'parameters'        => array(
							'driver'   => 'pdo_mysql',
							'host'     => 'db.example',
							'port'     => 3307,
							'dbname'   => 'logs',
							'user'     => 'logger',
							'password' => 'hunter2',
						),
					),
				),
			)
		);

		$handlers = array();

		foreach ( LoggingFactory::logger()->getHandlers() as $handler ) {
			if ( $handler instanceof DatabaseHandler ) {
				$handlers[ self::property( $handler, 'table' ) ] = $handler;
			}
		}

		$wordpress = $handlers[ $credentials->prefix_table( 'honoured_log' ) ] ?? null;

		$this->assertNotNull( $wordpress, 'The WordPress-connected handler is not writing to the prefixed table.' );
		$this->assertSame( 12, self::property( $wordpress, 'retentionDays' ) );
		$this->assertSame( 250, self::property( $wordpress, 'pruneBatchSize' ) );
		$this->assertSame( 4, self::property( $wordpress, 'pruneMaxBatches' ) );
		$this->assertFalse( self::property( $wordpress, 'buffered' ) );
		$this->assertSame( $parameters['dbname'], self::property( $wordpress, 'connectionParameters' )['dbname'] ?? null, 'WordPress\'s connection was not injected.' );

		$dsn = $handlers['honoured_dsn_log'] ?? null;

		$this->assertNotNull( $dsn );
		$this->assertSame( 5, self::property( $dsn, 'retentionDays' ) );
		$this->assertTrue( self::property( $dsn, 'buffered' ) );
		$this->assertSame( 'pdo-mysql://user:pass@db.example:3306/logs', self::property( $dsn, 'connectionParameters' )['dsn'] ?? null, 'The DSN did not reach the handler.' );

		$supplied = $handlers['honoured_parameters_log'] ?? null;

		$this->assertNotNull( $supplied );
		$this->assertSame(
			array( 'db.example', 3307, 'logs', 'logger' ),
			array(
				self::property( $supplied, 'connectionParameters' )['host'] ?? null,
				self::property( $supplied, 'connectionParameters' )['port'] ?? null,
				self::property( $supplied, 'connectionParameters' )['dbname'] ?? null,
				self::property( $supplied, 'connectionParameters' )['user'] ?? null,
			),
			'Connection parameters typed for a log handler did not reach it.'
		);
	}

	/**
	 * A rule answers to its id, and a disabled rule is not running.
	 */
	public function test_rule_identity(): void {
		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'office-range', 'ip_address', array( 'addresses' => '192.0.2.1' ) ),
					$this->rule( 'switched-off', 'ip_address', array( 'addresses' => '192.0.2.2' ), array( 'enabled' => false ) ),
				),
			)
		);

		$this->assertSame( 'office-range', $this->plugin_named( $firewall, 'office-range' )->getName() );
		$this->assertNull( $this->bucket_of( $firewall, 'switched-off' ) );
	}

	/**
	 * Each response lands in its bucket and does what it says.
	 */
	public function test_rule_responses(): void {
		$path = static fn ( string $path ): array => array( 'conditions' => array( self::condition( 'path', 'equals', $path ) ) );

		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule( 'let-in', 'url', $path( '/let-in' ), array( 'response' => 'allow' ) ),
					$this->rule(
						'send-away',
						'url',
						$path( '/send-away' ),
						array(
							'response'        => 'redirect',
							'redirect_to'     => '/elsewhere',
							'redirect_status' => 307,
						)
					),
					$this->rule(
						'note',
						'url',
						$path( '/note' ),
						array(
							'response'    => 'mark',
							'mark_as'     => 'suspicious',
							'mark_header' => 'X-Honoured-Mark',
						)
					),
					$this->rule( 'remember', 'url', $path( '/remember' ), array( 'response' => 'record' ) ),
					$this->rule(
						'refuse',
						'url',
						$path( '/refuse' ),
						array(
							'response' => 'block',
							'record'   => 'no',
						)
					),
					$this->rule( 'watch', 'url', $path( '/watch' ), array( 'observe' => true ) ),
					$this->rule(
						'late',
						'url',
						$path( '/order' ),
						array(
							'weight'      => 50,
							'status_code' => 418,
						)
					),
					$this->rule(
						'early',
						'url',
						$path( '/order' ),
						array(
							'weight'      => -50,
							'status_code' => 406,
						)
					),
				),
			)
		);

		$this->assertSame( 'allow', $this->bucket_of( $firewall, 'let-in' ) );
		$this->assertSame( 'redirect', $this->bucket_of( $firewall, 'send-away' ) );
		$this->assertSame( 'mark', $this->bucket_of( $firewall, 'note' ) );
		$this->assertSame( 'record', $this->bucket_of( $firewall, 'remember' ) );
		$this->assertSame( 'block', $this->bucket_of( $firewall, 'refuse' ) );

		$redirect = $this->outcome( $firewall, self::request( '/send-away', '203.0.113.91' ) );

		$this->assertSame( array( 'redirect', 307, '/elsewhere' ), array( $redirect['verdict'], $redirect['status'], $redirect['location'] ) );

		$marked = self::request( '/note', '203.0.113.92' );

		$this->assertSame( 'allow', $this->outcome( $firewall, $marked )['verdict'] );
		$this->assertSame( array( 'suspicious' ), $marked->attributes->get( 'firewall.marks' ) );
		$this->assertSame( 'suspicious', $marked->headers->get( 'X-Honoured-Mark' ) );

		$storage = self::property( $firewall, 'storage' );

		$this->assertSame( 'allow', $this->outcome( $firewall, self::request( '/remember', '203.0.113.93' ) )['verdict'] );
		$this->assertNotFalse( $storage->isBlocked( $storage->getKey( self::request( '/', '203.0.113.93' ) ) ), 'A record rule did not write the client to the block list.' );

		$this->assertSame( 'block', $this->outcome( $firewall, self::request( '/refuse', '203.0.113.94' ) )['verdict'] );
		$this->assertFalse( $storage->isBlocked( $storage->getKey( self::request( '/', '203.0.113.94' ) ) ), 'A block rule set not to record wrote to the block list.' );

		$this->assertTrue( $this->plugin_named( $firewall, 'watch' )->isObserveMode() );
		$this->assertSame( 'allow', $this->outcome( $firewall, self::request( '/watch', '203.0.113.95' ) )['verdict'], 'An observing rule refused a request.' );

		$this->assertSame( 406, $this->outcome( $firewall, self::request( '/order', '203.0.113.96' ) )['status'], 'The lower weight did not run first.' );
		$this->assertSame( 'allow', $this->outcome( $firewall, self::request( '/let-in', '203.0.113.97' ) )['verdict'] );
	}

	/**
	 * A rule outside its window is asleep, and one inside it is awake.
	 */
	public function test_rule_schedule(): void {
		$zone     = 'Pacific/Auckland';
		$today    = strtolower( ( new \DateTimeImmutable( 'now', new \DateTimeZone( $zone ) ) )->format( 'D' ) );
		$tomorrow = strtolower( ( new \DateTimeImmutable( 'tomorrow', new \DateTimeZone( $zone ) ) )->format( 'D' ) );
		$path     = array( 'conditions' => array( self::condition( 'path', 'equals', '/x' ) ) );

		$firewall = $this->build(
			array(
				'rules' => array(
					$this->rule(
						'awake',
						'url',
						$path,
						array(
							'schedule' => array(
								'timezone' => $zone,
								'days'     => array( $today ),
								'hours'    => '00:00-23:59',
								'from'     => '2000-01-01',
								'until'    => '2999-12-31',
							),
						)
					),
					$this->rule(
						'wrong-day',
						'url',
						$path,
						array(
							'schedule' => array(
								'timezone' => $zone,
								'days'     => array( $tomorrow ),
							),
						)
					),
					$this->rule(
						'not-yet',
						'url',
						$path,
						array(
							'schedule' => array(
								'timezone' => $zone,
								'from'     => '2999-01-01',
							),
						)
					),
					$this->rule(
						'over',
						'url',
						$path,
						array(
							'schedule' => array(
								'timezone' => $zone,
								'until'    => '2000-01-02',
							),
						)
					),
				),
			)
		);

		$sleeping = array_column( $firewall->getSleepingRules(), 'plugin' );

		$this->assertNotContains( 'awake', $sleeping );
		$this->assertContains( 'wrong-day', $sleeping );
		$this->assertContains( 'not-yet', $sleeping );
		$this->assertContains( 'over', $sleeping );
	}

	/**
	 * Leaf paths of the schema, with `*` for a list of maps.
	 *
	 * @param array<string, mixed> $node   Schema node.
	 * @param string               $prefix Path so far.
	 * @param list<string>         $leaves Collected paths, by reference.
	 */
	private static function schema_leaves( array $node, string $prefix, array &$leaves ): void {
		$type = (string) ( $node['type'] ?? '' );

		if ( 'map' === $type && isset( $node['children'] ) ) {
			foreach ( $node['children'] as $key => $child ) {
				self::schema_leaves( $child, '' === $prefix ? (string) $key : $prefix . '.' . $key, $leaves );
			}

			return;
		}

		if ( 'list' === $type && isset( $node['of']['children'] ) ) {
			self::schema_leaves( $node['of'], $prefix . '.*', $leaves );

			return;
		}

		$leaves[] = $prefix;
	}
}
