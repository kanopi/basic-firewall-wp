<?php
/**
 * Maps friendly configuration keys onto library class names.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Compiler;

use Kanopi\Firewall\Logging\Handler\DatabaseHandler;
use Kanopi\Firewall\Logging\Handler\DeferredHandler;
use Kanopi\Firewall\RateLimitStorage\DatabaseRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\FileRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\InMemoryRateLimitStorage;
use Kanopi\Firewall\RateLimitStorage\RedisRateLimitStorage;
use Kanopi\Firewall\Storage\DatabaseStorage;
use Kanopi\Firewall\Storage\FileStorage;
use Kanopi\Firewall\Storage\InMemoryStorage;
use Kanopi\Firewall\Storage\RecordedRequest;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\ErrorLogHandler;
use Monolog\Handler\RotatingFileHandler;
use Monolog\Handler\StreamHandler;

/**
 * Short configuration keys, and the class names they compile to.
 *
 * Stored settings use short keys -- `file`, `redis`, `rotating_file` -- rather
 * than class names. That keeps an export readable, keeps backslashes out of
 * option keys, and makes an upstream rename a change here rather than a data
 * migration on every site.
 *
 * **Every class name is written as a `::class` constant, never as a string,**
 * and that is load-bearing rather than stylistic. The release build runs this
 * tree through PHP-Scoper, which rewrites `::class` constants along with the
 * `use` statements above but treats a quoted `'Kanopi\\Firewall\\...'` as
 * ordinary text. A string here would survive scoping unchanged, get written
 * into the compiled file, and then fail `class_exists()` inside the library --
 * which responds by skipping the plugin and carrying on, so the firewall would
 * come up reporting success and enforcing nothing.
 *
 * That is the same failure this plugin's build gate exists to catch in the
 * library's own shipped YAML. Here it is avoided by construction instead.
 *
 * @see DECISIONS.md section 0.
 */
final class Library_Map {

	/**
	 * Blocked-client storage backends, keyed by configuration value.
	 *
	 * @var array<string, class-string>
	 */
	public const STORAGE = array(
		'memory'   => InMemoryStorage::class,
		'file'     => FileStorage::class,
		'database' => DatabaseStorage::class,
	);

	/**
	 * Rate limit counter backends, keyed by configuration value.
	 *
	 * @var array<string, class-string>
	 */
	public const RATE_LIMIT_STORAGE = array(
		'memory'   => InMemoryRateLimitStorage::class,
		'file'     => FileRateLimitStorage::class,
		'database' => DatabaseRateLimitStorage::class,
		'redis'    => RedisRateLimitStorage::class,
	);

	/**
	 * Log handlers offered in the interface.
	 *
	 * Handlers that wrap other handlers are excluded: the library's YAML loader
	 * cannot construct a nested HandlerInterface argument, so offering one would
	 * produce a configuration that saves and then fails to load.
	 *
	 * @var array<string, class-string>
	 */
	public const LOG_HANDLERS = array(
		'stream'        => StreamHandler::class,
		'rotating_file' => RotatingFileHandler::class,
		'error_log'     => ErrorLogHandler::class,
		'database'      => DatabaseHandler::class,
	);

	/**
	 * Handlers configured by one options map rather than positional arguments.
	 *
	 * Every Monolog handler takes its settings as ordered constructor
	 * arguments, which is why the compiler orders them by hand per handler. The
	 * library's own database handler takes a single associative array instead.
	 * The difference decides the shape of `logger[].args`, and guessing wrong
	 * produces a handler constructed with a table name where a level belongs.
	 *
	 * @var list<string>
	 */
	public const LOG_HANDLERS_KEYED = array( 'database' );

	/**
	 * The wrapper that moves a handler off the request path.
	 *
	 * Not in LOG_HANDLERS, because it is not a handler anybody chooses: it takes
	 * another handler as its first argument and holds records until the visitor
	 * has been served. Needs library 2.31.0, which is also the release that made
	 * a nested `{class, args}` expressible in `logger:` at all -- before it, a
	 * wrapping handler could not be configured, only written in PHP.
	 *
	 * @var class-string
	 */
	public const LOG_HANDLER_DEFERRED = DeferredHandler::class;

	/**
	 * Log formatters offered in the interface.
	 *
	 * @var array<string, class-string>
	 */
	public const LOG_FORMATTERS = array(
		'line' => LineFormatter::class,
		'json' => JsonFormatter::class,
	);

	/**
	 * Monolog severity levels, least to most severe.
	 *
	 * The values are enum-case references the library resolves when it reads the
	 * compiled file, not class names, so they are strings by necessity. They
	 * name `Monolog\Level`, which a scoped build renames -- so unlike the maps
	 * above, these are assembled from a `::class` constant at runtime rather
	 * than written out.
	 *
	 * @return array<string, string>
	 */
	public static function log_levels(): array {
		$enum = \Monolog\Level::class;

		return array(
			'debug'     => $enum . '::Debug',
			'info'      => $enum . '::Info',
			'notice'    => $enum . '::Notice',
			'warning'   => $enum . '::Warning',
			'error'     => $enum . '::Error',
			'critical'  => $enum . '::Critical',
			'alert'     => $enum . '::Alert',
			'emergency' => $enum . '::Emergency',
		);
	}

	/**
	 * Headers a block record keeps when nothing says otherwise.
	 *
	 * Read from the library rather than copied, because the plugin writes all
	 * four `record_request` buckets out explicitly -- a form cannot express the
	 * difference between "this bucket is absent, use your default" and "this
	 * bucket is empty, keep nothing" -- and a copied list would silently stop
	 * matching the library's the first time upstream adds a header to it.
	 *
	 * These are header names, not class names, so scoping does not touch them.
	 * Reading them through the class means a scoped build still asks the library
	 * that is actually in the zip.
	 *
	 * @return list<string>
	 */
	public static function default_recorded_headers(): array {
		return RecordedRequest::DEFAULT_HEADERS;
	}

	/**
	 * What `record_request` spells "keep everything in this bucket".
	 */
	public static function record_everything(): string {
		return RecordedRequest::EVERYTHING;
	}

	/**
	 * Operating modes the library understands.
	 *
	 * @var array<string, string>
	 */
	public const MODES = array(
		'block'     => 'Block matching requests',
		'log'       => 'Log only, block nothing',
		'exception' => 'Throw instead of responding',
		'disabled'  => 'Evaluate nothing',
	);

	/**
	 * Challenge providers the library ships.
	 *
	 * @var array<string, string>
	 */
	public const CHALLENGE_PROVIDERS = array(
		'math'      => 'Arithmetic — one addition, no JavaScript, no external script',
		'altcha'    => 'ALTCHA proof of work — costs bots CPU, single-use solutions',
		'turnstile' => 'Cloudflare Turnstile — verified by Cloudflare, usually no puzzle',
		'recaptcha' => 'Google reCAPTCHA — the checkbox (v2) or invisible scoring (v3)',
	);

	/**
	 * Providers that verify against a third party.
	 *
	 * These need credentials, send the visitor's browser to another origin, and
	 * make an outbound request while the visitor waits. A different proposition
	 * from the two that run entirely on the site, recorded once here rather than
	 * inferred from the provider name in several places.
	 *
	 * @var list<string>
	 */
	public const REMOTE_CHALLENGE_PROVIDERS = array( 'turnstile', 'recaptcha' );

	/**
	 * Resolve a short key to a class name.
	 *
	 * @param array<string, class-string> $map      One of the maps above.
	 * @param string                      $key      Configuration value.
	 * @param string                      $fallback Key to use when $key is unknown.
	 *
	 * @return class-string
	 */
	public static function resolve( array $map, string $key, string $fallback ): string {
		return $map[ $key ] ?? $map[ $fallback ];
	}
}
