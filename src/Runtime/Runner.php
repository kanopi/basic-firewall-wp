<?php
/**
 * Builds the firewall and evaluates the request.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Kanopi\BasicFirewall\Cache\Cache_Backend;
use Kanopi\BasicFirewall\Database_Credentials;
use Kanopi\BasicFirewall\Library_Loader;
use Kanopi\BasicFirewall\Logging\Redaction;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Redis_Password;
use Kanopi\Firewall\Firewall;
use Symfony\Component\HttpFoundation\Request;

/**
 * The normal evaluation path.
 *
 * **Failure posture: always fail open.** If the compiled file is missing,
 * unreadable or invalid, the request is allowed through and the problem is
 * reported in Site Health. A firewall misconfiguration will never be the reason
 * a site is unreachable. That is a deliberate choice with a cost -- a broken
 * firewall enforces nothing -- and the whole reason `require_config` defaults to
 * on is to make sure the failure is loud rather than silent.
 */
final class Runner {

	/**
	 * The wp-config.php constant that switches the firewall off entirely.
	 */
	public const ENABLED_CONSTANT = 'BASIC_FIREWALL_ENABLED';

	/**
	 * Where a mark is mirrored for code that reads request headers.
	 *
	 * `X-Firewall-Mark`, as PHP names a request header in `$_SERVER`.
	 */
	public const MARK_SERVER_KEY = 'HTTP_X_FIREWALL_MARK';

	/**
	 * Why evaluation did not happen, as a message key, or null.
	 *
	 * A key rather than a translated sentence, as in Library_Loader. The
	 * runner fails at `muplugins_loaded`, long before `init`, and calling
	 * __() there makes WordPress 6.7 and later report "translation loading
	 * was triggered too early" -- on every request, for as long as whatever
	 * stopped the firewall goes unfixed. The sentence is built when it is
	 * read, which is always an admin screen, Site Health or WP-CLI.
	 *
	 * @var string|null
	 */
	private static ?string $failure = null;

	/**
	 * What the failure message is about: an error message, usually.
	 *
	 * @var string
	 */
	private static string $failure_detail = '';

	/**
	 * Marks the firewall applied to this request.
	 *
	 * @var list<string>
	 */
	private static array $marks = array();

	/**
	 * Whether this request was exempt, as a member of an exempt role.
	 *
	 * @var bool
	 */
	private static bool $exempt = false;

	/**
	 * What this runner did with the request, for Diagnostics.
	 *
	 * `evaluated` is whether it built a firewall and evaluated the request
	 * itself; `outcome` the verdict it reached (`allowed`, `challenge`,
	 * `redirect`, `blocked`, `solved`) or null; `mode` the mode the firewall
	 * it built was actually in; `early_verdict` a verdict the wp-config.php
	 * path handed on to it rather than answering; `failed_rules` the rules
	 * the firewall it built could not construct, or null when this request
	 * did not sample them, and `failed_rules_sampled` why it did;
	 * `panic` whether a panic file was changing that firewall's mode.
	 *
	 * @var array{evaluated: bool, outcome: string|null, mode: string|null, early_verdict: string|null, failed_rules: list<string>|null, failed_rules_sampled: string|null, panic: bool}
	 */
	private static array $state = self::INITIAL_STATE;

	/**
	 * The state before anything has happened to the request.
	 */
	private const INITIAL_STATE = array(
		'evaluated'            => false,
		'outcome'              => null,
		'mode'                 => null,
		'early_verdict'        => null,
		'failed_rules'         => null,
		'failed_rules_sampled' => null,
		'panic'                => false,
	);

	/**
	 * Evaluate the current request.
	 *
	 * Never throws. Returns true when the request may continue -- which includes
	 * every failure case.
	 *
	 * @param Request|null $request Request to evaluate, or null for the current one.
	 */
	public function evaluate( ?Request $request = null ): bool {
		/*
		 * Before anything else, and on every branch: an `X-Firewall-Mark` the
		 * client sent is not a mark. The header is where this plugin mirrors
		 * the marks it applies, and code reading it has no way to tell the
		 * two apart -- so a scanner could otherwise mark itself as whatever a
		 * downstream check trusts, or pass itself off as unmarked. Only when
		 * evaluating the current request: a request handed in by a caller is
		 * not the one $_SERVER describes.
		 */
		if ( null === $request ) {
			self::forget_client_marks();
		}

		if ( defined( 'BASIC_FIREWALL_EVALUATED' ) ) {
			/*
			 * The wp-config.php path already dealt with this request -- but it
			 * did so before WordPress existed, so anything it wants to announce
			 * has been waiting in a global for somewhere to announce it, and
			 * anything it could not answer has been waiting to be answered.
			 */
			$this->adopt_early_marks();
			$this->adopt_early_failure();

			$handed_on = self::early_outcome();

			if ( null !== $handed_on ) {
				self::$state['early_verdict'] = Outcome_Responder::verdict_kind( $handed_on['outcome'] );
			}

			$this->refuse_unanswered_early_verdict();

			return $this->answer_early_outcome();
		}

		if ( ! $this->is_enabled() ) {
			return true;
		}

		/*
		 * An exempt role. Only the current request, because only its cookies
		 * are there to read. See Role_Bypass for why this splits on a cookie.
		 */
		$bypass = null === $request ? $this->bypass_decision( $_COOKIE ) : 'evaluate';

		if ( 'defer' === $bypass ) {
			/*
			 * Not yet: the login cookie cannot be validated before the
			 * pluggable functions load. Left unmarked, so the runner's
			 * `plugins_loaded` hook evaluates it -- or exempts it -- then.
			 */
			return true;
		}

		if ( 'exempt' === $bypass ) {
			define( 'BASIC_FIREWALL_EVALUATED', true );

			self::$exempt = true;

			return true;
		}

		if ( ! Library_Loader::is_usable() ) {
			self::$failure = 'library';

			return true;
		}

		define( 'BASIC_FIREWALL_EVALUATED', true );

		$compiled = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $compiled ) ) {
			self::$failure = 'no-compiled-file';

			return true;
		}

		return $this->evaluate_compiled( $compiled, $request );
	}

	/**
	 * Build the firewall from the compiled file and evaluate the request.
	 *
	 * Split from evaluate() so the failure handling can be driven directly:
	 * the test suite's own process is marked as evaluated before WordPress
	 * loads, so evaluate() always takes the wp-config.php branch there.
	 *
	 * @param string       $compiled The compiled configuration file.
	 * @param Request|null $request  Request to evaluate, or null for the current one.
	 */
	private function evaluate_compiled( string $compiled, ?Request $request ): bool {
		$this->define_cache_constants();

		/*
		 * Before the firewall is built, because every address-based rule depends
		 * on it. Symfony only honours a forwarding header once this is
		 * established; until then every visitor behind the proxy shares one
		 * address, and one visitor's offense blocks the lot.
		 */
		Trusted_Proxies::apply();

		// Before the firewall exists, so nothing is logged unredacted first.
		$this->apply_redaction();

		try {
			/*
			 * The dispatcher is what makes a decision reachable from WordPress
			 * at all -- see Decision_Dispatcher for why it announces later than
			 * it is told. It is given the pass cookie's name so it can tell a
			 * challenged visitor their pass did not come back (#46).
			 */
			$firewall = Firewall::create( array( $compiled ), $this->overrides(), new Decision_Dispatcher( Plugin::instance()->compiled()->pass_cookie() ) );
		} catch ( \Throwable $e ) {
			/*
			 * With require_config on, the library refuses to start rather than
			 * running with a partial ruleset that allows everything and looks
			 * like success. This is where that refusal lands: logged, reported,
			 * and then failed open on. Traffic is treated the same as it would
			 * have been; the difference is that somebody finds out.
			 */
			self::$failure        = 'could-not-start';
			self::$failure_detail = $e->getMessage();

			Diagnostics::warn_fail_open( 'runner', $e, 'the firewall could not start' );

			return true;
		}

		self::$state['evaluated'] = true;
		self::$state['mode']      = $firewall->getMode()->value;
		self::$state['panic']     = (bool) ( $firewall->getPanicSwitch()['active'] ?? false );

		/*
		 * The rules this firewall could not construct (#41) -- sampled, not
		 * asked on every request, because answering means building every
		 * rule and undoing the library's lazy construction. See
		 * Diagnostics::sample_failed_rules(). Asked before evaluating when
		 * it is asked, since a request the library refuses ends inside
		 * evaluate().
		 */
		self::sample_failed_rules( $firewall, Diagnostics::debug_enabled() ? 'debug' : null );

		/*
		 * The request is built here rather than left to the library, so that
		 * the marks can be read back off it afterwards.
		 *
		 * A `mark` response sets `firewall.marks` as an attribute on the Symfony
		 * Request, for the application downstream to act on. WordPress has no
		 * idea that object exists -- so without this, `mark` is a response type
		 * the rule screen offers and nothing on the site can ever observe.
		 *
		 * Through Request_Factory, as the wp-config.php path does, so both
		 * paths hand the library the same request -- including a logged-in
		 * request deferred to `plugins_loaded`, which is evaluated here. The
		 * library then matches a directly requested file (wp-login.php, a
		 * wp-admin screen) on the file the server ran, under the compiled
		 * `path_source: script_name`.
		 */
		$request = $request ?? Request_Factory::from_globals();

		try {
			$allowed = $firewall->evaluate( $request );

			self::$state['outcome'] = 'allowed';

			$this->publish_marks( $request );

			return $allowed;
		} catch ( \Throwable $e ) {
			self::$state['outcome'] = Outcome_Responder::verdict_kind( $e );

			// Before the responder writes anything, because it ends the request.
			Diagnostics::send_header();

			// A blocking exception is the library's way of saying "rejected" in
			// exception mode. The responder decides what the visitor sees.
			$allowed = ( new Outcome_Responder() )->respond( $e, $request );

			/*
			 * The responder ends the request for every verdict, so reaching
			 * here means what was thrown was not one: the firewall failed
			 * partway through evaluating, and the request goes on unfiltered.
			 * That is the fail-open this class promises, and it used to be a
			 * silent one -- nothing recorded it, so Site Health reported a
			 * healthy firewall on the request it had just waved through.
			 */
			if ( $allowed ) {
				self::record_evaluation_failure( $e );

				/*
				 * Logged as well: the failure recorded above reaches Site
				 * Health only on the request it happened on, which is a
				 * visitor's and never the administrator's. Rate-limited per
				 * exception and place, with a count; see warn_fail_open().
				 */
				Diagnostics::warn_fail_open( 'runner', $e, 'the firewall failed while evaluating the request' );

				// A failure samples regardless: the cost does not matter here.
				self::sample_failed_rules( $firewall, 'failure' );
			}

			return $allowed;
		}
	}

	/**
	 * Record the firewall's failed rules, when this request is one that samples.
	 *
	 * @param Firewall    $firewall The firewall.
	 * @param string|null $reason   `debug` or `failure` to ask regardless, or null when the interval decides.
	 */
	private static function sample_failed_rules( Firewall $firewall, ?string $reason ): void {
		if ( null !== self::$state['failed_rules_sampled'] ) {
			return;
		}

		$sample = Diagnostics::sample_failed_rules( $firewall, $reason );

		self::$state['failed_rules']         = $sample['failed_rules'];
		self::$state['failed_rules_sampled'] = $sample['sampled'];
	}

	/**
	 * Record that evaluation itself failed, rather than deciding anything.
	 *
	 * @param \Throwable $e What the firewall threw.
	 */
	private static function record_evaluation_failure( \Throwable $e ): void {
		self::$failure        = 'evaluation-failed';
		self::$failure_detail = get_class( $e ) . ': ' . $e->getMessage();
	}

	/**
	 * Answer an `exception` mode verdict the wp-config.php path left behind.
	 *
	 * The bootstrap answers refusals itself, before a page cache can serve the
	 * page. What it leaves here is a solved challenge, which needs settings to
	 * set the pass cookie -- and, only if this copy of the plugin is missing
	 * its responder, a refusal it had no way to answer. Either way it is
	 * answered here, at `muplugins_loaded` when the loader is installed, and
	 * at `plugins_loaded` when it is not. Late, but answered: dropping it would
	 * serve a refused visitor the page.
	 *
	 * Taken out of the global before it is answered, so nothing answers it
	 * twice.
	 */
	private function answer_early_outcome(): bool {
		$early = self::early_outcome();

		if ( null === $early ) {
			return true;
		}

		unset( $GLOBALS['basic_firewall_outcome'] );

		Diagnostics::send_header();

		return ( new Outcome_Responder() )->respond( $early['outcome'], $early['request'] );
	}

	/**
	 * Refuse a request the wp-config.php path reached a verdict on and let through.
	 *
	 * The bootstrap answers every refusal itself and ends the request, and
	 * leaves only a solved challenge behind. So a request arriving here with
	 * a challenge, redirect or block recorded and nothing left to answer is
	 * one the early path failed open on -- #34, a challenge rule serving the
	 * page it stands in front of. A bootstrap from this release refuses such
	 * a verdict itself; this is the tripwire for everything else, an older
	 * bootstrap.php still required from wp-config.php among them. Late, after
	 * a page cache has had its chance, but it refuses the request, logs why,
	 * and leaves the failure for Site Health rather than serving the page.
	 */
	private function refuse_unanswered_early_verdict(): void {
		$kind = $GLOBALS['basic_firewall_early']['outcome'] ?? null;

		if ( ! in_array( $kind, array( 'challenge', 'redirect', 'blocked' ), true ) || null !== self::early_outcome() ) {
			return;
		}

		self::$failure        = 'evaluation-failed';
		self::$failure_detail = sprintf( 'the wp-config.php path reached a %s verdict and let the request continue', $kind );

		self::$state['early_verdict'] = $kind;

		/*
		 * Saved now, because the refusal below ends the request: this is the
		 * report somebody investigating most needs, and a shutdown function
		 * is not a promise.
		 */
		if ( Diagnostics::is_web_request() ) {
			Diagnostics::persist();
		}

		Diagnostics::send_header();

		( new Outcome_Responder() )->refuse( $kind, self::$failure_detail );
	}

	/**
	 * The verdict the wp-config.php path left for WordPress to answer, if any.
	 *
	 * @return array{outcome: \Throwable, request: Request|null}|null
	 */
	public static function early_outcome(): ?array {
		$stash = $GLOBALS['basic_firewall_outcome'] ?? null;

		if ( ! is_array( $stash ) || ! ( ( $stash['outcome'] ?? null ) instanceof \Throwable ) ) {
			return null;
		}

		return array(
			'outcome' => $stash['outcome'],
			'request' => ( $stash['request'] ?? null ) instanceof Request ? $stash['request'] : null,
		);
	}

	/**
	 * Take up an evaluation failure the wp-config.php path recorded.
	 *
	 * The bootstrap fails open on anything the firewall throws that is not a
	 * verdict, as this class does, and leaves what it caught in its report so
	 * the failure is not lost with the request it happened on.
	 */
	private function adopt_early_failure(): void {
		$failure = $GLOBALS['basic_firewall_early']['failure'] ?? null;

		if ( is_string( $failure ) && '' !== $failure && null === self::$failure ) {
			self::$failure        = 'evaluation-failed';
			self::$failure_detail = $failure;
		}
	}

	/**
	 * Announce marks the wp-config.php path recorded before WordPress loaded.
	 */
	private function adopt_early_marks(): void {
		$marks = $GLOBALS['basic_firewall_marks'] ?? null;

		if ( ! is_array( $marks ) || array() === $marks || array() !== self::$marks ) {
			return;
		}

		self::$marks = array_values( array_map( 'strval', $marks ) );

		foreach ( self::$marks as $mark ) {
			$_SERVER[ self::MARK_SERVER_KEY ] = $mark;
		}

		/** This filter is documented in src/Runtime/Runner.php */
		do_action( 'basic_firewall_request_marked', self::$marks, null );
	}

	/**
	 * Hand any marks the firewall set to WordPress.
	 *
	 * A marked request is allowed through and flagged -- the honeypot case,
	 * where you want to know who tripped a rule without telling them they did.
	 * The library records that on the Symfony Request; this makes it reachable
	 * from a theme, a plugin, or a logging hook.
	 *
	 * @param Request $request The evaluated request.
	 */
	private function publish_marks( Request $request ): void {
		$marks = $request->attributes->get( 'firewall.marks' );

		if ( ! is_array( $marks ) || array() === $marks ) {
			return;
		}

		self::$marks = array_values( array_map( 'strval', $marks ) );

		/*
		 * Mirrored into $_SERVER so that code reading headers the ordinary way
		 * sees it, which is how a mark reaches something that was never written
		 * to know this plugin exists.
		 */
		foreach ( self::$marks as $mark ) {
			$_SERVER[ self::MARK_SERVER_KEY ] = $mark;
		}

		/**
		 * Fires when the firewall marked this request without refusing it.
		 *
		 * @param list<string> $marks   The marks applied, each a rule identifier
		 *                              or the rule's configured mark name.
		 * @param Request      $request The evaluated request.
		 */
		do_action( 'basic_firewall_request_marked', self::$marks, $request );
	}

	/**
	 * Drop any `X-Firewall-Mark` header the client sent.
	 *
	 * The header is the plugin's to set, so one that arrived with the request
	 * is removed before evaluation rather than left for code downstream to
	 * mistake for a mark. The wp-config.php path does the same in
	 * bootstrap.php, before WordPress exists to call this.
	 */
	public static function forget_client_marks(): void {
		unset( $_SERVER[ self::MARK_SERVER_KEY ] );
	}

	/**
	 * The marks the firewall applied to this request.
	 *
	 * @return list<string>
	 */
	public static function marks(): array {
		return self::$marks;
	}

	/**
	 * Whether the firewall marked this request with a given name.
	 *
	 * @param string $mark Mark name.
	 */
	public static function is_marked( string $mark ): bool {
		return in_array( $mark, self::$marks, true );
	}

	/**
	 * What the role exemption says about the current request.
	 *
	 * `evaluate` for a request no exemption applies to -- no role is exempt,
	 * or it carries no login cookie -- which is every request on a site that
	 * never configured one. `defer` when it carries a login cookie and the
	 * cookie cannot be validated yet, at `muplugins_loaded`. `exempt` when it
	 * validates, for a member of an exempt role.
	 *
	 * @param array<mixed> $cookies The request's cookies.
	 */
	private function bypass_decision( array $cookies ): string {
		$roles = Role_Bypass::clean( (array) Plugin::instance()->settings()->get( 'global.bypass_roles', array() ) );

		if ( array() === $roles || ! Role_Bypass::carries_login_cookie( $cookies ) ) {
			return 'evaluate';
		}

		if ( ! Role_Bypass::can_authenticate() ) {
			return 'defer';
		}

		return Role_Bypass::exempts( $roles ) ? 'exempt' : 'evaluate';
	}

	/**
	 * Whether this request went unevaluated as a member of an exempt role.
	 */
	public static function exempted(): bool {
		return self::$exempt;
	}

	/**
	 * Whether the firewall should run at all.
	 *
	 * The constant is checked first and needs no database access, which is what
	 * makes it the documented way out of a lockout.
	 */
	public function is_enabled(): bool {
		if ( defined( self::ENABLED_CONSTANT ) && false === constant( self::ENABLED_CONSTANT ) ) {
			return false;
		}

		return (bool) Plugin::instance()->settings()->get( 'enabled', true );
	}

	/**
	 * Redact the site's own names from the log, as well as the library's.
	 *
	 * The library has no configuration key for these, so they are handed to
	 * it directly -- here from settings, and on the wp-config.php path from
	 * the runtime sidecar. See Redaction.
	 */
	private function apply_redaction(): void {
		Redaction::apply( (array) Plugin::instance()->settings()->get( 'logging.redact_extra', array() ) );
	}

	/**
	 * Runtime overrides applied over the compiled file.
	 *
	 * @return array<string, mixed>
	 */
	private function overrides(): array {
		$overrides = array();

		/*
		 * A mode pinned in wp-config.php stays pinned, panic file or not. The
		 * compiler already writes the constant's mode into the file, but the
		 * library applies a panic file over whatever mode the configuration
		 * arrived at -- so an environment that pins its mode would otherwise
		 * have it changed by a file nobody deployed. The bootstrap does the
		 * same on the other path.
		 */
		if ( defined( 'BASIC_FIREWALL_MODE' ) ) {
			$overrides['[global][panic_file]'] = '';
		}

		/*
		 * Live database credentials, injected at the paths the compiler
		 * recorded. They are never written into the compiled file -- see
		 * Database_Credentials for why a baked snapshot goes stale silently on a
		 * platform that rotates them.
		 */
		$paths = Plugin::instance()->compiled()->connection_paths();

		if ( array() !== $paths ) {
			$credentials = ( new Database_Credentials() )->get_connection_parameters();

			if ( array() !== $credentials ) {
				foreach ( $paths as $path ) {
					$overrides[ $path ] = $credentials;
				}
			}
		}

		/*
		 * The Redis password, when wp-config.php supplies it, injected at
		 * every Redis connection the compiler recorded -- the block list and
		 * each rate limit's counters. With the constant defined the compiled
		 * file holds no password at all; see Redis_Password. The bootstrap does
		 * the same on the other path, from the constant and a sidecar.
		 */
		$redis_password = Redis_Password::from_constant();

		if ( null !== $redis_password ) {
			foreach ( Plugin::instance()->compiled()->redis_auth_paths() as $path => $username ) {
				$overrides[ $path ] = Redis_Password::auth( $username, $redis_password );
			}
		}

		/*
		 * The object cache, if that is where the site caches. Handed over
		 * live because YAML cannot carry an object; the other backends are in
		 * the compiled file already and add nothing here.
		 */
		$overrides += Cache_Backend::overrides();

		/**
		 * Filters the runtime overrides applied over the compiled configuration.
		 *
		 * Overrides are applied at runtime and never written to disk, which
		 * makes this the right place to vary the firewall per environment --
		 * the equivalent of the module's `basic_firewall_config_overrides`.
		 *
		 * @param array<string, mixed> $overrides Symfony property-access paths to values.
		 */
		return apply_filters( 'basic_firewall_config_overrides', $overrides );
	}

	/**
	 * Point the library's parse cache somewhere writable and persistent.
	 *
	 * This is the single biggest performance factor in the whole plugin: 0.08 ms
	 * to read the compiled configuration from the parse cache against 42 ms to
	 * parse the YAML. Left to its own devices the library falls back to the
	 * system temporary directory, which gets cleared -- and every clear costs
	 * that 42 ms again, on every php-fpm worker.
	 */
	private function define_cache_constants(): void {
		if ( ! defined( 'KANOPI_FIREWALL_CACHE_DIR' ) ) {
			define( 'KANOPI_FIREWALL_CACHE_DIR', Plugin::instance()->paths()->library_cache_dir() );
		}

		if ( ! defined( 'KANOPI_FIREWALL_SOURCES_OFFLINE' ) ) {
			/*
			 * Only an explicit false opts out. Anything else, the constant being
			 * absent included, keeps network access off the request path -- a
			 * firewall that makes an outbound HTTP call while a visitor waits is
			 * a firewall that fails when the network does.
			 */
			define(
				'KANOPI_FIREWALL_SOURCES_OFFLINE',
				! ( defined( 'BASIC_FIREWALL_SOURCES_OFFLINE' ) && false === constant( 'BASIC_FIREWALL_SOURCES_OFFLINE' ) )
			);
		}
	}

	/**
	 * Backends that built but could not reach what they were configured with.
	 *
	 * Never throws. A firewall that cannot be built at all is a different
	 * problem, reported by a different check, and this one returning nothing is
	 * the right answer to "what degraded" when the answer is "everything".
	 *
	 * Needs library 2.28.0, which composer.json now requires. Before it these
	 * backends did not degrade -- they stopped the firewall starting, which on
	 * a blocking site meant no protection rather than less.
	 *
	 * @return list<array<string, mixed>>
	 */
	public function degraded_backends(): array {
		$firewall = $this->build_for_reporting();

		if ( null === $firewall ) {
			return array();
		}

		return array_values( $firewall->getDegradedBackends() );
	}

	/**
	 * An armed panic switch, as the library sees it.
	 *
	 * A panic file is not in the compiled configuration -- it is a path the
	 * library stats on each request -- so asking a firewall is the only way to
	 * know whether one is in force. Reading the mode out of settings, or out
	 * of the compiled file, cannot see it at all, which is exactly how a site
	 * comes to be reported as blocking three weeks after somebody wrote `log`
	 * into a file during an incident and went to bed.
	 *
	 * @return array{active: bool, path: string|null, problem: string|null, configured: string, effective: string}|null
	 *         Null when nothing is armed, or it is armed with no file present.
	 */
	public function panic_switch(): ?array {
		$firewall = $this->build_for_reporting();

		if ( null === $firewall ) {
			return null;
		}

		$switch  = $firewall->getPanicSwitch();
		$active  = (bool) ( $switch['active'] ?? false );
		$problem = $switch['problem'] ?? null;

		/*
		 * A path with nothing at it is the ordinary state of an armed switch,
		 * and reporting it would make the signal worthless. A file that exists
		 * and cannot be used is worth reporting: somebody wrote it expecting it
		 * to do something.
		 */
		if ( ! $active && ( ! is_string( $problem ) || '' === $problem ) ) {
			return null;
		}

		return array(
			'active'     => $active,
			'path'       => is_string( $switch['path'] ?? null ) ? $switch['path'] : null,
			'problem'    => is_string( $problem ) && '' !== $problem ? $problem : null,

			// Both, so a report can say what changed and what comes back when
			// the file goes, rather than leaving an operator to work it out.
			'configured' => $firewall->getConfiguredMode()->value,
			'effective'  => $this->effective_mode( $firewall, $switch['mode'] ?? null ),
		);
	}

	/**
	 * The mode a panic file put the firewall in, as somebody would name it.
	 *
	 * `lockdown` in the file is shorthand the library unpacks into lockdown
	 * delivered the way `block` delivers, so the firewall itself reports
	 * `block`. Repeating that back -- "a panic file is forcing block mode, the
	 * configured mode is block" -- would describe a site that is refusing
	 * every visitor as though nothing had changed.
	 *
	 * @param Firewall $firewall  The firewall that read the file.
	 * @param mixed    $requested What the file asked for.
	 */
	private function effective_mode( Firewall $firewall, $requested ): string {
		if ( $requested instanceof \BackedEnum && 'lockdown' === $requested->value ) {
			return 'lockdown';
		}

		return $firewall->getMode()->value;
	}

	/**
	 * Whether the firewall is refusing everyone but the lockdown allowlist.
	 *
	 * Asked of the library rather than read from settings, because there are
	 * three ways in and only one is the setting: `global.lockdown`, `mode:
	 * lockdown` in the Advanced YAML, and a panic file naming `lockdown`. A
	 * status page reading settings alone would miss the two most likely to be
	 * in force during an incident.
	 */
	public function is_locked_down(): bool {
		$firewall = $this->build_for_reporting();

		return null !== $firewall && $firewall->isLockedDown();
	}

	/**
	 * A firewall built to be asked questions, never to evaluate.
	 *
	 * Asked of a firewall built for the purpose rather than of the one that
	 * evaluated this request, because on an admin screen there was no such
	 * request: the early path answered it before WordPress existed, or this is
	 * WP-CLI. Building one costs a parse the library has already cached.
	 *
	 * Never throws. A configuration the library refuses outright is reported
	 * by the compiled-configuration check, so a failure here is null rather
	 * than a second report of the same thing.
	 */
	private function build_for_reporting(): ?Firewall {
		if ( ! Library_Loader::is_usable() ) {
			return null;
		}

		$compiled = Plugin::instance()->paths()->compiled_file();

		if ( ! is_readable( $compiled ) ) {
			return null;
		}

		$this->define_cache_constants();

		try {
			return Firewall::create( array( $compiled ), $this->overrides() );
		} catch ( \Throwable $e ) {
			return null;
		}
	}

	/**
	 * Why the last evaluation did not happen, or null.
	 *
	 * Translated here, when it is read, rather than when it happened; see
	 * $failure.
	 */
	public static function failure(): ?string {
		switch ( self::$failure ) {
			case null:
				return null;

			case 'library':
				return Library_Loader::failure() ?? __( 'The firewall library is not available.', 'basic-firewall' );

			case 'no-compiled-file':
				return __( 'There is no compiled configuration, so no rules were evaluated. Rebuild the firewall.', 'basic-firewall' );

			case 'evaluation-failed':
				return sprintf(
					/* translators: %s: exception class and message. */
					__( 'The firewall failed while evaluating the request, and let it through unfiltered: %s', 'basic-firewall' ),
					self::$failure_detail
				);

			case 'could-not-start':
				return sprintf(
					/* translators: %s: error message. */
					__( 'The firewall could not start, so no rules were evaluated: %s', 'basic-firewall' ),
					self::$failure_detail
				);

			default:
				return self::$failure;
		}
	}

	/**
	 * Clear the recorded failure. Test seam.
	 *
	 * @internal
	 */
	public static function reset(): void {
		self::$failure        = null;
		self::$failure_detail = '';
		self::$marks          = array();
		self::$exempt         = false;
		self::$state          = self::INITIAL_STATE;
	}

	/**
	 * What this runner did with the current request, for Diagnostics.
	 *
	 * `failure` is the machine key of why evaluation did not happen or did
	 * not finish, and `failure_detail` what it was about; `exempt` whether an
	 * exempt role skipped evaluation.
	 *
	 * @return array{evaluated: bool, outcome: string|null, mode: string|null, early_verdict: string|null, failed_rules: list<string>|null, failed_rules_sampled: string|null, panic: bool, failure: string|null, failure_detail: string, exempt: bool}
	 */
	public static function state(): array {
		return self::$state + array(
			'failure'        => self::$failure,
			'failure_detail' => self::$failure_detail,
			'exempt'         => self::$exempt,
		);
	}
}
