<?php
/**
 * The plugin container.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall;

use Kanopi\BasicFirewall\Install\Capabilities;
use Kanopi\BasicFirewall\Install\Upgrader;
use Kanopi\BasicFirewall\Support\Paths;

/**
 * Wires the plugin together and owns the shared services.
 *
 * Deliberately small. A plugin-sized service container that is not Drupal's
 * container should be legible in one screen, and everything it holds is
 * lazily constructed so that a request which only needs the runtime does not
 * pay to build the admin.
 */
final class Plugin {

	/**
	 * The singleton.
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Lazily built services, keyed by name.
	 *
	 * @var array<string, object>
	 */
	private array $services = array();

	/**
	 * Whether register() has run.
	 */
	private bool $registered = false;

	/**
	 * Private: use instance().
	 */
	private function __construct() {}

	/**
	 * The shared instance.
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Attach the plugin's hooks.
	 *
	 * Runs on every request, so it does as little as possible: registering
	 * callbacks, never doing work. Anything that reads the database, touches the
	 * filesystem or builds the firewall happens inside those callbacks.
	 */
	public function register(): void {
		if ( $this->registered ) {
			return;
		}

		$this->registered = true;

		/*
		 * Upgrade routines run before anything else reads settings, so that a
		 * document written by an older release is migrated before it is used
		 * rather than after something has already misread it.
		 */
		add_action( 'plugins_loaded', array( Upgrader::class, 'maybe_upgrade' ), 1 );

		add_action( 'init', array( $this, 'load_textdomain' ) );
	}

	/**
	 * Load translations.
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain( 'basic-firewall', false, dirname( plugin_basename( BASIC_FIREWALL_FILE ) ) . '/languages' );
	}

	/**
	 * The settings service.
	 */
	public function settings(): Settings {
		return $this->service( 'settings', static fn(): Settings => new Settings() );
	}

	/**
	 * The path resolver.
	 */
	public function paths(): Paths {
		return $this->service( 'paths', static fn(): Paths => new Paths() );
	}

	/**
	 * Build or fetch a service.
	 *
	 * @template T of object
	 *
	 * @param string          $name    Service key.
	 * @param callable(): T   $factory Builds it on first use.
	 *
	 * @return T
	 */
	private function service( string $name, callable $factory ): object {
		if ( ! isset( $this->services[ $name ] ) ) {
			$this->services[ $name ] = $factory();
		}

		/** @var T */
		return $this->services[ $name ];
	}

	/**
	 * Replace a service. Test seam.
	 *
	 * @param string $name    Service key.
	 * @param object $service Replacement.
	 *
	 * @internal
	 */
	public function set_service( string $name, object $service ): void {
		$this->services[ $name ] = $service;
	}

	/**
	 * Drop the singleton. Test seam.
	 *
	 * @internal
	 */
	public static function reset(): void {
		self::$instance = null;
	}
}
