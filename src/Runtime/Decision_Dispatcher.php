<?php
/**
 * Hands the firewall's decisions to WordPress actions.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Runtime;

use Kanopi\BasicFirewall\Challenge\Pass_Cookie;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The PSR-14 dispatcher the library announces each decision on.
 *
 * The Drupal module passes Drupal's own dispatcher, because it is already
 * PSR-14 and a decision arrives as an ordinary Drupal event. WordPress has no
 * dispatcher to hand over; its equivalent is an action. So this is the smallest
 * PSR-14 dispatcher that turns each decision into two of them:
 *
 *     do_action( 'basic_firewall_decision', $event, $type );
 *     do_action( "basic_firewall_decision_{$type}", $event );
 *
 * **Announced late, on purpose.** The firewall evaluates at `muplugins_loaded`,
 * before a single regular plugin or theme has loaded -- so an action fired there
 * reaches only listeners attached from an mu-plugin, and a plugin listening for
 * decisions would hear nothing on the ordinary path. Decisions are therefore
 * held and announced at `plugins_loaded`, once plugins have had the chance to
 * attach. A refusal ends the request before that: it is announced at shutdown
 * instead, by which time only mu-plugins are loaded, because that is all
 * WordPress got as far as loading.
 *
 * The same queue carries the wp-config.php path. There, WordPress does not exist
 * yet and there is nothing to announce on, so decisions wait for it the way a
 * mark does. A refusal on that path exits before WordPress ever loads, so it is
 * never announced at all -- the one decision this cannot deliver, and it is said
 * in the readme rather than papered over.
 *
 * **Loaded without the autoloader** on the wp-config.php path, like
 * Database_Credentials, so it depends on nothing but the PSR interface the
 * vendored autoloader already provides. Calling any WordPress function here
 * before checking it exists is a fatal error on every request.
 *
 * **Nothing a listener does changes the verdict.** The events carry no setters
 * and the return value of an action is discarded. By the time anything is
 * announced the decision is made, and in the terminating modes the response is
 * already on its way.
 *
 * **The one thing done synchronously: a notice on the challenge page** (#46).
 * The library dispatches `RequestChallenged` before it writes the interstitial
 * and reads the event's notices back into the page, in `block` mode on its
 * own page and in `exception` mode through the render context the plugin
 * renders from (kanopi/firewall 2.35.0). A visitor who solved a challenge a
 * moment ago and came back without the pass cookie is told so here, at
 * dispatch, because by the time the event is announced to WordPress the page
 * has been written. The condition is Pass_Cookie::went_missing(), so both
 * modes and both evaluation paths show the same line from the same code.
 */
final class Decision_Dispatcher implements EventDispatcherInterface {

	/**
	 * The generic action every decision is announced on.
	 */
	public const ACTION = 'basic_firewall_decision';

	/**
	 * The library's event classes, by the name the per-type action uses.
	 *
	 * Keyed on the short class name because in a release build the library is
	 * namespace-scoped, so the full name differs between a release zip and a
	 * Composer install. A listener comparing `$type` works in both; one
	 * type-hinting `Kanopi\Firewall\Event\RequestBlocked` works in only one.
	 */
	private const TYPES = array(
		'RequestAllowed'    => 'allowed',
		'RequestBlocked'    => 'blocked',
		'RequestChallenged' => 'challenged',
		'ChallengeSolved'   => 'challenge_solved',
		'ChallengeFailed'   => 'challenge_failed',
		'RequestRecorded'   => 'recorded',
		'RequestRedirected' => 'redirected',
		'RequestMarked'     => 'marked',
		'RequestTarpitted'  => 'tarpitted',
	);

	/**
	 * Decisions waiting for WordPress to be ready to hear them.
	 *
	 * @var list<object>
	 */
	private static array $pending = array();

	/**
	 * Whether the shutdown announcement has been registered.
	 *
	 * @var bool
	 */
	private static bool $shutdown = false;

	/**
	 * The pass cookie's name, as the compiled file gives it to the library.
	 *
	 * @var string
	 */
	private string $pass_cookie;

	/**
	 * Set up the dispatcher for one firewall.
	 *
	 * @param string $pass_cookie The pass cookie's name: the runner's compiled
	 *                            record, or the runtime sidecar's on the
	 *                            wp-config.php path. Empty adds no notice.
	 */
	public function __construct( string $pass_cookie = '' ) {
		$this->pass_cookie = $pass_cookie;
	}

	/**
	 * Hold a decision until it can be announced.
	 *
	 * @param object $event The library's decision event.
	 */
	public function dispatch( object $event ): object {
		$this->add_notices( $event );
		$this->set_marker( $event );

		self::$pending[] = $event;

		/*
		 * Evaluation that happens once plugins have loaded -- the fallback for a
		 * site without the mu-plugin loader -- has nothing to wait for.
		 */
		if ( function_exists( 'did_action' ) && did_action( 'plugins_loaded' ) ) {
			self::announce();

			return $event;
		}

		/*
		 * A refusal exits before plugins_loaded, and PHP still runs shutdown
		 * functions after exit(). Registered through PHP rather than the
		 * `shutdown` action because on the wp-config.php path there are no
		 * actions yet; announce() declines there if WordPress never arrived.
		 */
		if ( ! self::$shutdown ) {
			self::$shutdown = true;

			register_shutdown_function( array( self::class, 'announce' ) );
		}

		return $event;
	}

	/**
	 * Put the missing-pass line on the page a challenged visitor is about to see.
	 *
	 * Only a `RequestChallenged` from a library that takes notices (2.35.0),
	 * and only when the solved marker is there without the pass. Never lets a
	 * failure out: a notice that could not be added leaves the page as it was,
	 * and the challenge is served either way.
	 *
	 * @param object $event The library's decision event.
	 */
	private function add_notices( object $event ): void {
		if ( '' === $this->pass_cookie || 'challenged' !== self::type( $event ) || ! method_exists( $event, 'addNotice' ) || ! method_exists( $event, 'getRequest' ) ) {
			return;
		}

		try {
			$request = $event->getRequest();

			if ( ! is_object( $request ) || ! isset( $request->cookies ) || ! is_object( $request->cookies ) || ! method_exists( $request->cookies, 'all' ) ) {
				return;
			}

			if ( ! self::load_pass_cookie() ) {
				return;
			}

			if ( Pass_Cookie::went_missing( $this->pass_cookie, (array) $request->cookies->all() ) ) {
				$event->addNotice( Pass_Cookie::missing_notice() );
			}
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Set the solved marker beside a pass the library is about to issue.
	 *
	 * In `block` mode the library answers a solution itself: it sets the pass
	 * cookie and ends the request, and nothing of this plugin runs after. The
	 * marker that lets the next challenge say the pass went missing (#37) was
	 * set only by the runner, which answers solutions in `exception` mode, so
	 * `block` mode never had one to see (#46). The library announces the solve
	 * just before it sets the pass, while headers can still be sent, so the
	 * marker goes out here, on whichever path evaluated the solution. The
	 * runner leaves out a marker already queued.
	 *
	 * @param object $event The library's decision event.
	 */
	private function set_marker( object $event ): void {
		if ( '' === $this->pass_cookie || 'challenge_solved' !== self::type( $event ) || ! method_exists( $event, 'getRequest' ) || headers_sent() ) {
			return;
		}

		try {
			$request = $event->getRequest();

			if ( ! self::load_pass_cookie() ) {
				return;
			}

			$secure = is_object( $request ) && method_exists( $request, 'isSecure' ) && (bool) $request->isSecure();
			$marker = Pass_Cookie::marker_cookie( $this->pass_cookie, $secure );

			// Once per response, if a second firewall on this request announces the same solve.
			if ( false !== stripos( implode( "\n", headers_list() ), 'Set-Cookie: ' . $marker['name'] . '=' ) ) {
				return;
			}

			setcookie( $marker['name'], $marker['value'], $marker['options'] );
		} catch ( \Throwable $e ) {
			return;
		}
	}

	/**
	 * Make Pass_Cookie available, loading it by hand if the autoloader cannot.
	 *
	 * The wp-config.php path loads this class by hand, and Pass_Cookie beside
	 * it the same way, for the same reason: it depends on nothing.
	 */
	private static function load_pass_cookie(): bool {
		if ( class_exists( Pass_Cookie::class ) ) {
			return true;
		}

		$file = dirname( __DIR__ ) . '/Challenge/Pass_Cookie.php';

		if ( is_readable( $file ) ) {
			require_once $file;
		}

		return class_exists( Pass_Cookie::class, false );
	}

	/**
	 * Announce every held decision.
	 *
	 * Hooked to `plugins_loaded`, and registered for shutdown as well. Safe to
	 * call any number of times: the queue is emptied before anything is
	 * announced, so a listener that somehow triggers another announcement does
	 * not see the same decision twice.
	 */
	public static function announce(): void {
		if ( array() === self::$pending || ! function_exists( 'do_action' ) ) {
			return;
		}

		$events        = self::$pending;
		self::$pending = array();

		foreach ( $events as $event ) {
			$type = self::type( $event );

			/*
			 * A listener that throws is not an outage. The library isolates the
			 * listeners it calls itself; these run outside it, after the
			 * decision, so the isolation is repeated here. The cost is WordPress's
			 * own: an exception ends the rest of that action's callbacks for this
			 * decision, because do_action() has no per-callback isolation.
			 */
			try {
				/**
				 * Fires for every decision the firewall made about this request.
				 *
				 * Announced at `plugins_loaded`, or at shutdown when a refusal ended
				 * the request first. Nothing a callback does changes the verdict.
				 *
				 * @param object $event The library's decision event. Duck-type it --
				 *                      `getRequest()`, `isEnforced()`, and on a block
				 *                      `getPlugin()` and `getStatusCode()` -- rather
				 *                      than type-hinting its class, which is
				 *                      namespace-scoped in a release build.
				 * @param string $type  `allowed`, `blocked`, `challenged`,
				 *                      `challenge_solved`, `challenge_failed`,
				 *                      `recorded`, `redirected`, `marked` or
				 *                      `tarpitted`.
				 */
				do_action( 'basic_firewall_decision', $event, $type );

				/**
				 * Fires for one kind of decision, named by `$type` as above.
				 *
				 * @param object $event The library's decision event.
				 */
				do_action( 'basic_firewall_decision_' . $type, $event );
			} catch ( \Throwable $e ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- the firewall's own logger is gone by now, and a listener failure nobody can find is the silent kind this plugin exists to avoid.
				error_log(
					sprintf(
						'Basic Firewall: a basic_firewall_decision listener threw on a %s decision, and was ignored: %s',
						$type,
						$e->getMessage()
					)
				);
			}
		}
	}

	/**
	 * The name the per-type action uses for an event.
	 *
	 * A class the table does not know -- one a later library release adds --
	 * still gets a stable name rather than being dropped, derived the same way
	 * the table's names are.
	 *
	 * @param object $event The library's decision event.
	 */
	public static function type( object $event ): string {
		$class = get_class( $event );
		$short = substr( (string) strrchr( '\\' . $class, '\\' ), 1 );

		if ( isset( self::TYPES[ $short ] ) ) {
			return self::TYPES[ $short ];
		}

		$name = (string) preg_replace( '/^Request(?=[A-Z])/', '', $short );

		return strtolower( (string) preg_replace( '/(?<!^)[A-Z]/', '_$0', $name ) );
	}

	/**
	 * The decisions still waiting. Test seam.
	 *
	 * @internal
	 *
	 * @return list<object>
	 */
	public static function pending(): array {
		return self::$pending;
	}

	/**
	 * Forget every held decision. Test seam.
	 *
	 * @internal
	 */
	public static function reset(): void {
		self::$pending = array();
	}
}
