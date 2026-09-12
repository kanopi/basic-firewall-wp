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
use Kanopi\BasicFirewall\Compiler\Compiled_Config_Cache;
use Kanopi\BasicFirewall\RuleType\Registry;
use Kanopi\BasicFirewall\Runtime\Runner;
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

		/*
		 * Both evaluation paths converge here.
		 *
		 * The mu-plugin fires basic_firewall_early_evaluate at
		 * muplugins_loaded, which is the earliest a plugin-owned hook can run.
		 * The wp-config.php bootstrap calls the runner directly and never
		 * reaches this, which is what the BASIC_FIREWALL_EVALUATED guard is for.
		 *
		 * plugins_loaded is the fallback for a site whose mu-plugin could not be
		 * installed -- later than we would like, but the alternative is not
		 * evaluating at all.
		 */
		add_action( 'basic_firewall_early_evaluate', array( $this, 'evaluate' ), 0 );
		add_action( 'plugins_loaded', array( $this, 'evaluate' ), 2 );

		/*
		 * The compiled file is a cache of the settings option, so it is rebuilt
		 * whenever that option changes rather than on a timer or on a request
		 * that happens to notice it is stale.
		 */
		add_action( 'basic_firewall_settings_saved', array( $this, 'rebuild' ) );
		add_action( 'basic_firewall_activated', array( $this, 'rebuild' ) );
		add_action( 'basic_firewall_upgraded', array( $this, 'rebuild' ) );
	}

	/**
	 * Load translations.
	 */
	public function load_textdomain(): void {
		load_plugin_textdomain( 'basic-firewall', false, dirname( plugin_basename( BASIC_FIREWALL_FILE ) ) . '/languages' );
	}

	/**
	 * Evaluate the current request.
	 */
	public function evaluate(): void {
		$this->runner()->evaluate();
	}

	/**
	 * The runtime runner.
	 */
	public function runner(): Runner {
		return $this->service( 'runner', static fn(): Runner => new Runner() );
	}

	/**
	 * Rebuild the compiled configuration.
	 */
	public function rebuild(): void {
		$this->compiled()->rebuild();
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
	 * The compiled configuration cache.
	 */
	public function compiled(): Compiled_Config_Cache {
		return $this->service( 'compiled', static fn(): Compiled_Config_Cache => new Compiled_Config_Cache() );
	}

	/**
	 * The blocked client store.
	 */
	public function blocked(): Blocked_Clients {
		return $this->service( 'blocked', static fn(): Blocked_Clients => new Blocked_Clients() );
	}

	/**
	 * The preset library.
	 */
	public function presets(): Preset_Library {
		return $this->service( 'presets', static fn(): Preset_Library => new Preset_Library() );
	}

	/**
	 * The rule type registry.
	 */
	public function rule_types(): Registry {
		return $this->service( 'rule_types', static fn(): Registry => new Registry() );
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
