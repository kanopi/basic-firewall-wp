<?php
/**
 * Compiles settings through the real pipeline and hands back the library's firewall.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Support\Schema;
use Kanopi\Firewall\Diagnostics\ConfigLinter;
use Kanopi\Firewall\Diagnostics\Diagnosis;
use Kanopi\Firewall\Exception\ChallengeRequiredException;
use Kanopi\Firewall\Exception\FirewallBlockedException;
use Kanopi\Firewall\Exception\FirewallLockdownException;
use Kanopi\Firewall\Exception\FirewallRedirectException;
use Kanopi\Firewall\Firewall;
use Kanopi\Firewall\Plugins\PluginInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Yaml\Yaml;

/**
 * Base class for the tests that prove the library acts on what the screens save.
 *
 * Every defect in this family looked the same from the outside. A setting was
 * saved, compiled to a key the library does not read -- `challenge.options`
 * where it reads `challenge.provider_options.<name>`, `anomaly_threshold` where
 * it reads `anomaly_thresholds`, `storage-table` where it reads `storage_table`
 * -- and the rule loaded, Site Health said healthy, and the setting did
 * nothing. A test comparing the compiled array with what the compiler was
 * meant to write only restates the compiler: it passes on exactly the mistake.
 *
 * So these helpers run the same path a request does. Settings are written to
 * the option (and so through every rule type's validator), the compiled file is
 * rebuilt by the plugin's own cache, the library is started on that file with
 * the runner's own runtime overrides, and the test then asks *the library* what
 * it ended up with -- by evaluating a request, or by reading the value back out
 * of the object that would enforce it.
 */
abstract class Honoured_Settings extends Settings_Snapshot {

	/**
	 * Problems the last rebuild reported.
	 *
	 * @var list<string>
	 */
	protected array $problems = array();

	/**
	 * The last compiled file, parsed.
	 *
	 * @var array<string, mixed>
	 */
	protected array $compiled = array();

	/**
	 * Scratch directory for block lists, counters and logs.
	 *
	 * Nothing a test evaluates is allowed to land in the site's own block list:
	 * these run against a real site, and a test fixture refusing an address
	 * there would outlive the test.
	 *
	 * @var string
	 */
	protected string $scratch = '';

	/**
	 * Trusted proxies as found, put back afterwards.
	 *
	 * @var array{0: list<string>, 1: int}
	 */
	private array $proxies = array( array(), 0 );

	/**
	 * Make a scratch directory.
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->scratch = sys_get_temp_dir() . '/bfw-honoured-' . bin2hex( random_bytes( 4 ) );

		wp_mkdir_p( $this->scratch );

		$this->proxies = array( Request::getTrustedProxies(), Request::getTrustedHeaderSet() );
	}

	/**
	 * Remove it, and put the trusted proxies back.
	 */
	protected function tearDown(): void {
		Request::setTrustedProxies( $this->proxies[0], $this->proxies[1] );

		self::remove_tree( $this->scratch );

		parent::tearDown();
	}

	/**
	 * Settings every build starts from.
	 *
	 * Exception mode because under the command line the library bypasses
	 * itself in every other mode. Block records go to the scratch directory.
	 *
	 * @return array<string, mixed>
	 */
	protected function base_settings(): array {
		return array(
			'enabled'   => true,
			'global'    => array(
				'mode'         => 'exception',
				'behind_proxy' => 'no',
				'panic_file'   => '',
			),
			'storage'   => array(
				'backend' => 'file',
				'file'    => array(
					'storage_file' => $this->scratch . '/blocked.data',
					'offense_file' => $this->scratch . '/blocked.data.offenses',
				),
			),
			// A secret of its own, so no test depends on the site having one.
			'challenge' => array( 'secret' => str_repeat( 's', 48 ) ),
			'logger'    => array(),
			'presets'   => array(),
		);
	}

	/**
	 * Save settings, rebuild the compiled file, and start the library on it.
	 *
	 * @param array<string, mixed> $overrides Merged over base_settings() and the schema defaults.
	 * @param bool                 $raw       Write the option without validating it, as an old
	 *                                        release or a hand edit would have left it.
	 */
	protected function build( array $overrides, bool $raw = false ): Firewall {
		$settings = self::merge( $this->base_settings(), $overrides );

		if ( $raw ) {
			update_option( Schema::OPTION, self::merge( Schema::defaults(), $settings ), false );
			Plugin::instance()->settings()->flush();
		} else {
			$this->given_settings( $settings );
		}

		return $this->start();
	}

	/**
	 * Rebuild the compiled file from the stored settings, and start the library on it.
	 *
	 * Separate from build() for a test that stores its settings some other
	 * way -- through the importer, say.
	 */
	protected function start(): Firewall {
		$result = Plugin::instance()->compiled()->rebuild();

		$this->assertTrue( $result['written'], 'The compiled file was not written: ' . implode( ' ', $result['problems'] ) );

		$this->problems = $result['problems'];
		$this->compiled = (array) Yaml::parseFile( Plugin::instance()->paths()->compiled_file() );

		$runner = Plugin::instance()->runner();

		self::invoke( $runner, 'define_cache_constants' );

		try {
			$firewall = Firewall::create( array( Plugin::instance()->paths()->compiled_file() ), (array) self::invoke( $runner, 'overrides' ) );
		} catch ( \Throwable $e ) {
			$this->fail( sprintf( 'The library refused to start on the compiled file, so the plugin fails open and nothing is enforced: %s: %s', get_class( $e ), $e->getMessage() ) );
		}

		$this->assertSame( array(), $firewall->getFailedRules(), 'A compiled rule could not be constructed by the library.' );

		/*
		 * The library's own linter as well. It does not know every key a
		 * plugin reads -- which is why the tests ask the constructed objects
		 * -- but it does catch a rule that can never match, an undeclared
		 * connection and a schedule it cannot read.
		 */
		$errors = array_filter(
			( new ConfigLinter( array( Plugin::instance()->paths()->compiled_file() ) ) )->run(),
			static fn ( Diagnosis $diagnosis ): bool => Diagnosis::ERROR === $diagnosis->status
		);

		$this->assertSame( array(), array_map( static fn ( Diagnosis $diagnosis ): string => $diagnosis->title . ': ' . $diagnosis->detail, array_values( $errors ) ), 'The library\'s linter found an error in the compiled file.' );

		return $firewall;
	}

	/**
	 * A complete stored rule.
	 *
	 * @param string               $id       Rule id, which is also the library's name for it.
	 * @param string               $type     Rule type.
	 * @param array<string, mixed> $settings Type settings.
	 * @param array<string, mixed> $extra    Rule-level fields.
	 *
	 * @return array<string, mixed>
	 */
	protected function rule( string $id, string $type, array $settings, array $extra = array() ): array {
		return array_merge(
			array(
				'id'                 => $id,
				'type'               => $type,
				'label'              => $id,
				'enabled'            => true,
				'observe'            => false,
				'response'           => 'block',
				'weight'             => 0,
				'status_code'        => 0,
				'record'             => 'default',
				'redirect_to'        => '',
				'redirect_status'    => 302,
				'mark_as'            => '',
				'mark_header'        => '',
				'challenge_provider' => '',
				'expiration'         => 600,
				'settings'           => $settings,
			),
			$extra
		);
	}

	/**
	 * A one-condition rule's settings.
	 *
	 * @param string $variable Variable.
	 * @param string $operator Operator.
	 * @param string $value    Value.
	 *
	 * @return array<string, mixed>
	 */
	protected static function condition( string $variable, string $operator, string $value ): array {
		return array(
			'variable'       => $variable,
			'operator'       => $operator,
			'value'          => $value,
			'negate'         => false,
			'case_sensitive' => false,
		);
	}

	/**
	 * The constructed library plugin answering to a name.
	 *
	 * @param Firewall $firewall The firewall.
	 * @param string   $name     The rule id.
	 */
	protected function plugin_named( Firewall $firewall, string $name ): PluginInterface {
		foreach ( (array) self::invoke( $firewall, 'buckets' ) as $manager ) {
			if ( null === $manager ) {
				continue;
			}

			foreach ( $manager->getPlugins() as $plugin ) {
				if ( $plugin->getName() === $name ) {
					return $plugin;
				}
			}
		}

		$this->fail( "The library is not running a rule called $name." );
	}

	/**
	 * The bucket a rule was partitioned into.
	 *
	 * @param Firewall $firewall The firewall.
	 * @param string   $name     The rule id.
	 */
	protected function bucket_of( Firewall $firewall, string $name ): ?string {
		foreach ( (array) self::invoke( $firewall, 'buckets' ) as $bucket => $manager ) {
			if ( null === $manager ) {
				continue;
			}

			foreach ( $manager->getPlugins() as $plugin ) {
				if ( $plugin->getName() === $name ) {
					return (string) $bucket;
				}
			}
		}

		return null;
	}

	/**
	 * What the library decides about a request.
	 *
	 * @param Firewall $firewall The firewall.
	 * @param Request  $request  The request.
	 *
	 * @return array{verdict: string, status: int|null, message: string, location: string|null}
	 */
	protected function outcome( Firewall $firewall, Request $request ): array {
		try {
			$allowed = $firewall->evaluate( $request );

			return array(
				'verdict'  => $allowed ? 'allow' : 'block',
				'status'   => null,
				'message'  => '',
				'location' => null,
			);
		} catch ( FirewallRedirectException $e ) {
			return array(
				'verdict'  => 'redirect',
				'status'   => $e->getStatusCode(),
				'message'  => $e->getMessage(),
				'location' => $e->getLocation(),
			);
		} catch ( FirewallLockdownException $e ) {
			return array(
				'verdict'  => 'lockdown',
				'status'   => $e->getStatusCode(),
				'message'  => $e->getMessage(),
				'location' => null,
			);
		} catch ( FirewallBlockedException $e ) {
			return array(
				'verdict'  => 'block',
				'status'   => $e->getStatusCode(),
				'message'  => $e->getMessage(),
				'location' => null,
			);
		} catch ( ChallengeRequiredException $e ) {
			return array(
				'verdict'  => 'challenge',
				'status'   => null,
				'message'  => $e->getMessage(),
				'location' => null,
			);
		}
	}

	/**
	 * A request from an address.
	 *
	 * @param string                $path    Path and query.
	 * @param string                $ip      Client address.
	 * @param array<string, string> $headers Headers.
	 * @param string                $method  Method.
	 */
	protected static function request( string $path = '/', string $ip = '203.0.113.200', array $headers = array(), string $method = 'GET' ): Request {
		$request = Request::create( $path, $method, array(), array(), array(), array( 'REMOTE_ADDR' => $ip ) );

		$request->headers->set( 'User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36' );

		foreach ( $headers as $name => $value ) {
			$request->headers->set( $name, $value );
		}

		return $request;
	}

	/**
	 * Call a method whatever its visibility.
	 *
	 * @param object|string $target Object, or class for a static method.
	 * @param string        $method Method.
	 * @param mixed         ...$args Arguments.
	 *
	 * @return mixed
	 */
	protected static function invoke( $target, string $method, ...$args ) {
		$reflector = new \ReflectionMethod( $target, $method );
		$reflector->setAccessible( true );

		return $reflector->invoke( is_object( $target ) ? $target : null, ...$args );
	}

	/**
	 * Read a property whatever its visibility, walking up to the class declaring it.
	 *
	 * @param object $target Object.
	 * @param string $name   Property.
	 *
	 * @return mixed
	 */
	protected static function property( object $target, string $name ) {
		$class = new \ReflectionClass( $target );

		while ( ! $class->hasProperty( $name ) && false !== $class->getParentClass() ) {
			$class = $class->getParentClass();
		}

		$reflector = $class->getProperty( $name );
		$reflector->setAccessible( true );

		return $reflector->getValue( $target );
	}

	/**
	 * Replace a property whatever its visibility.
	 *
	 * @param object $target Object.
	 * @param string $name   Property.
	 * @param mixed  $value  Value.
	 */
	protected static function set_property( object $target, string $name, $value ): void {
		$class = new \ReflectionClass( $target );

		while ( ! $class->hasProperty( $name ) && false !== $class->getParentClass() ) {
			$class = $class->getParentClass();
		}

		$reflector = $class->getProperty( $name );
		$reflector->setAccessible( true );
		$reflector->setValue( $target, $value );
	}

	/**
	 * Every leaf of a nested settings array, as dotted paths.
	 *
	 * A list counts as a leaf: it is one field on a screen, however many
	 * entries it holds.
	 *
	 * @param array<string, mixed> $values Settings.
	 * @param string               $prefix Path so far.
	 *
	 * @return list<string>
	 */
	protected static function leaves( array $values, string $prefix = '' ): array {
		$paths = array();

		foreach ( $values as $key => $value ) {
			$path = '' === $prefix ? (string) $key : $prefix . '.' . $key;

			if ( is_array( $value ) && array() !== $value && ! array_is_list( $value ) ) {
				$paths = array_merge( $paths, self::leaves( $value, $path ) );

				continue;
			}

			$paths[] = $path;
		}

		return $paths;
	}

	/**
	 * Recursive merge where lists are replaced, not combined.
	 *
	 * @param array<mixed> $base     Base.
	 * @param array<mixed> $override Override.
	 *
	 * @return array<mixed>
	 */
	protected static function merge( array $base, array $override ): array {
		foreach ( $override as $key => $value ) {
			if ( is_array( $value ) && isset( $base[ $key ] ) && is_array( $base[ $key ] ) && ! array_is_list( $value ) && ! array_is_list( $base[ $key ] ) ) {
				$base[ $key ] = self::merge( $base[ $key ], $value );

				continue;
			}

			$base[ $key ] = $value;
		}

		return $base;
	}

	/**
	 * Remove a directory and everything in it.
	 *
	 * @param string $directory Directory.
	 */
	private static function remove_tree( string $directory ): void {
		if ( '' === $directory || ! is_dir( $directory ) ) {
			return;
		}

		$items = new \RecursiveIteratorIterator(
			new \RecursiveDirectoryIterator( $directory, \FilesystemIterator::SKIP_DOTS ),
			\RecursiveIteratorIterator::CHILD_FIRST
		);

		foreach ( $items as $item ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions -- a scratch directory under the system temp dir.
			$item->isDir() ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions -- as above.
		rmdir( $directory );
	}
}
