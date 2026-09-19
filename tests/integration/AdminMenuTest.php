<?php
/**
 * The admin menu, as the plugin actually wires it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Admin;
use Kanopi\BasicFirewall\Admin\Screen\Challenge_Screen;
use Kanopi\BasicFirewall\Plugin;
use Kanopi\BasicFirewall\Install\Capabilities;
use PHPUnit\Framework\TestCase;

/**
 * That there is a way in.
 *
 * This suite exists because the plugin shipped without one. `Admin::register()`
 * was never called from `Plugin::register()` -- an edit that silently failed to
 * apply -- and nothing caught it for eleven commits, because every test reached
 * the admin the wrong way:
 *
 * - one called `Admin::render()` directly, which renders a screen whether or not
 *   anything ever registered a menu to reach it from;
 * - another called `Admin::register()` by hand and then checked the menu, which
 *   proves the registration code works and nothing about whether it runs.
 *
 * So these assert on the hooks the PLUGIN wired, never on anything this file
 * registers. The distinction is the whole point: a firewall nobody can configure
 * is not a firewall, and it looked completely healthy from WP-CLI.
 */
final class AdminMenuTest extends TestCase {

	/**
	 * The top-level menu entry, captured once.
	 *
	 * @var array<int, mixed>|null
	 */
	private static ?array $top = null;

	/**
	 * The submenu slugs, captured once.
	 *
	 * @var list<string>
	 */
	private static array $submenus = array();

	/**
	 * Fire admin_menu once for the whole class, and keep what it produced.
	 *
	 * Once, deliberately. WordPress's menu registration is not idempotent --
	 * firing the hook a second time in the same process does not repopulate
	 * $submenu, so a per-test do_action() has the first test pass and every one
	 * after it assert against an empty array.
	 */
	public static function setUpBeforeClass(): void {
		parent::setUpBeforeClass();

		/*
		 * add_menu_page() and add_submenu_page() live in an admin include that
		 * a CLI bootstrap never loads. A site that has been browsed has it
		 * warm; a freshly installed one in CI does not, and the whole class
		 * died on an undefined function rather than on anything about the menu.
		 */
		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		global $menu, $submenu;

		/*
		 * The capabilities are granted through a filter rather than by logging
		 * a user in.
		 *
		 * add_submenu_page() drops any entry the CURRENT user cannot reach, so
		 * with nobody logged in the top-level entry appeared and every submenu
		 * silently vanished -- which reads exactly like the registration bug
		 * this class was written to catch. Granting via user_has_cap keeps the
		 * test about the plugin's wiring and independent of which accounts this
		 * site happens to have.
		 */
		add_filter(
			'user_has_cap',
			static function ( array $caps ): array {
				foreach ( Capabilities::all() as $capability ) {
					$caps[ $capability ] = true;
				}

				return $caps;
			}
		);

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- firing WordPress's own hook is the point of this test.
		do_action( 'admin_menu' );

		foreach ( (array) $menu as $item ) {
			if ( isset( $item[2] ) && Admin::MENU === $item[2] ) {
				self::$top = $item;
			}
		}

		foreach ( (array) ( $submenu[ Admin::MENU ] ?? array() ) as $item ) {
			self::$submenus[] = (string) $item[2];
		}
	}

	/**
	 * The plugin must have hooked admin_menu by itself.
	 */
	public function test_the_plugin_registers_its_admin_menu(): void {
		$this->assertNotFalse(
			has_action( 'admin_menu' ),
			'Nothing is hooked to admin_menu. The plugin has no way into its own settings.'
		);
	}

	/**
	 * The top-level menu exists, and is reachable by somebody who can read reports.
	 */
	public function test_the_top_level_menu_is_registered(): void {
		$found = self::$top;

		$this->assertNotNull( $found, 'There is no Firewall entry in the admin menu.' );

		/*
		 * Reports, not manage. Support staff need to answer "why can't this
		 * customer reach the site?" without also being able to rewrite the rule
		 * set -- gating the menu on the management capability would hide the
		 * dashboard from exactly the people who need it most.
		 */
		$this->assertSame(
			Capabilities::VIEW_REPORTS,
			$found[1],
			'The menu is gated on the wrong capability.'
		);
	}

	/**
	 * Every screen that belongs in the menu is in it.
	 */
	public function test_every_menu_screen_is_reachable(): void {
		$registered = self::$submenus;

		$this->assertNotEmpty( $registered, 'The Firewall menu has no submenu items.' );

		foreach ( Admin::screens() as $slug => $screen ) {
			if ( ! $screen->in_menu() ) {
				continue;
			}

			$this->assertContains(
				$slug,
				$registered,
				sprintf( '%s declares itself a menu screen but is not in the menu.', $slug )
			);
		}
	}

	/**
	 * A screen reached by URL is capability-checked on its own.
	 *
	 * The capability passed to add_submenu_page() governs the menu only. A
	 * screen reached by typing its URL has to check for itself, or the menu is
	 * decoration.
	 */
	public function test_every_screen_declares_a_capability_this_plugin_owns(): void {
		foreach ( Admin::screens() as $slug => $screen ) {
			$this->assertContains(
				$screen->capability(),
				Capabilities::all(),
				sprintf( '%s is gated on a capability this plugin does not define.', $slug )
			);
		}
	}

	/**
	 * The screens reached by link rather than by menu are still registered.
	 *
	 * WordPress will not render a page it was never told about, so a screen left
	 * out of the menu has to be registered with a null parent or every link to
	 * it is a permissions error.
	 */
	public function test_screens_outside_the_menu_are_still_registered(): void {
		$hidden = array();

		foreach ( Admin::screens() as $slug => $screen ) {
			if ( ! $screen->in_menu() ) {
				$hidden[] = $slug;
			}
		}

		$this->assertNotEmpty( $hidden, 'Expected at least the rule editor to be reached by link.' );

		foreach ( $hidden as $slug ) {
			$this->assertArrayHasKey(
				$slug,
				Admin::screens(),
				sprintf( '%s is linked to but not registered.', $slug )
			);
		}
	}

	/**
	 * The sidebar reads in the order somebody works in.
	 *
	 * Pinned because it is an ordering, and an ordering is the kind of thing a
	 * later edit reshuffles without anyone noticing: where things stand, then
	 * what the firewall is configured to do, then what it has actually done,
	 * then moving that configuration somewhere else.
	 */
	public function test_the_menu_is_in_order(): void {
		$reflector = new \ReflectionMethod( Admin::class, 'screens' );
		$reflector->setAccessible( true );

		$order = array();

		foreach ( $reflector->invoke( null ) as $screen ) {
			if ( $screen->in_menu() ) {
				$order[] = $screen->slug();
			}
		}

		$this->assertSame(
			array(
				'basic-firewall',
				'basic-firewall-general',
				'basic-firewall-storage',
				'basic-firewall-rules',
				'basic-firewall-logging',
				'basic-firewall-challenge',
				'basic-firewall-presets',
				'basic-firewall-advanced',
				'basic-firewall-log',
				'basic-firewall-blocked',
				'basic-firewall-compiled',
				'basic-firewall-export',
				'basic-firewall-import',
				'basic-firewall-test',
			),
			$order
		);
	}

	/**
	 * The first entry is named for what it answers.
	 *
	 * WordPress labels a top-level page's first child with the parent's own
	 * title unless told otherwise, which read "Firewall / Firewall" -- the one
	 * entry that says whether anything is wrong, indistinguishable from the
	 * section containing it.
	 */
	public function test_the_first_entry_is_status(): void {
		$reflector = new \ReflectionMethod( Admin::class, 'screens' );
		$reflector->setAccessible( true );

		$screens = array_values( $reflector->invoke( null ) );

		$this->assertSame( 'basic-firewall', $screens[0]->slug() );
		$this->assertSame( 'Status', $screens[0]->menu_title() );
	}

	/**
	 * Each page renders once.
	 *
	 * The Status screen rendered twice, top to bottom, on every load. A submenu
	 * whose slug equals its parent's resolves to the same page hook as the
	 * parent, so registering it with a callback added a second listener to the
	 * hook `add_menu_page()` had already registered one on. Nothing about the
	 * menu looked wrong -- the entry count and the order were both correct --
	 * which is why this asserts on the callbacks rather than on the menu.
	 */
	public function test_no_page_is_registered_twice(): void {
		global $menu, $submenu, $wp_filter;

		/*
		 * Emptied so this measures one call rather than whatever the admin has
		 * accumulated. phpcs objects to assigning WordPress globals, and is
		 * right to in production code; a test that builds the menu has to start
		 * from an empty one.
		 */
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$menu = array();
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$submenu = array();

		require_once ABSPATH . 'wp-admin/includes/plugin.php';

		/*
		 * Cleared first, because the menu has already been built once by the
		 * time a test runs and callbacks accumulate. Counting without this
		 * measures how many times `add_menu()` was called rather than how many
		 * listeners one call leaves behind, which is the actual question.
		 */
		foreach ( array_keys( $wp_filter ) as $hook ) {
			if ( 1 === preg_match( '/_page_' . preg_quote( Admin::MENU, '/' ) . '/', (string) $hook ) ) {
				unset( $wp_filter[ $hook ] );
			}
		}

		Admin::add_menu();

		$reflector = new \ReflectionMethod( Admin::class, 'screens' );
		$reflector->setAccessible( true );

		foreach ( $reflector->invoke( null ) as $screen ) {
			$hook = get_plugin_page_hookname( $screen->slug(), $screen->slug() === Admin::MENU ? '' : Admin::MENU );

			if ( ! isset( $wp_filter[ $hook ] ) ) {
				continue;
			}

			$callbacks = 0;

			foreach ( $wp_filter[ $hook ]->callbacks as $priority ) {
				$callbacks += count( $priority );
			}

			$this->assertLessThanOrEqual(
				1,
				$callbacks,
				sprintf( 'The %s screen is registered %d times, so it renders that many times.', $screen->slug(), $callbacks )
			);
		}
	}

	/**
	 * Choosing a challenge provider shows that provider's settings at once.
	 *
	 * Only the saved provider's section used to render, which made its settings
	 * unreachable at the one moment somebody wants them: pick Google reCAPTCHA
	 * and nothing appears -- no keys, and no way to say whether you want the
	 * checkbox or the invisible scoring one -- until the form has been saved
	 * and reloaded. Choosing a provider and configuring it is one decision.
	 */
	public function test_every_challenge_provider_is_configurable_without_saving_first(): void {
		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();

		try {
			$values                          = $settings->all();
			$values['challenge']['provider'] = 'math';
			$settings->replace( $values );

			// The screen closes its form with submit_button(), which lives in
			// an admin include the test bootstrap has no reason to load.
			require_once ABSPATH . 'wp-admin/includes/template.php';

			ob_start();
			( new Challenge_Screen() )->render();
			$rendered = (string) ob_get_clean();

			foreach ( array(
				'options[recaptcha][version]',
				'options[recaptcha][min_score]',
				'options[turnstile][site_key]',
				'options[altcha][widget_src]',
			) as $field ) {
				$this->assertStringContainsString(
					$field,
					$rendered,
					sprintf( '%s is missing while another provider is selected, so it cannot be set without saving twice.', $field )
				);
			}

			// And each section is gated, or every provider's fields show at once.
			foreach ( array( 'provider:math', 'provider:altcha', 'provider:turnstile', 'provider:recaptcha' ) as $condition ) {
				$this->assertStringContainsString( $condition, $rendered );
			}
		} finally {
			$settings->replace( $snapshot );
		}
	}

	/**
	 * Both reCAPTCHA versions are offered, and the choice reaches the library.
	 */
	public function test_recaptcha_version_reaches_the_compiled_config(): void {
		$settings = Plugin::instance()->settings();
		$snapshot = $settings->all();

		try {
			$values                          = $settings->all();
			$values['challenge']['provider'] = 'recaptcha';
			$values['challenge']['provider_options']['recaptcha'] = array(
				'site_key'   => 'site',
				'secret_key' => 'secret',
				'version'    => 'v3',
				'min_score'  => 0.7,
				'action'     => 'login',
			);

			$settings->replace( $values );

			$this->assertSame( 'v3', $settings->get( 'challenge.provider_options.recaptcha.version' ) );

			Plugin::instance()->compiled()->rebuild();

			$compiled = (string) Plugin::instance()->compiled()->contents();

			$this->assertStringContainsString( 'version: v3', $compiled, 'The version never reached the library, so the choice did nothing.' );
			$this->assertStringContainsString( 'min_score: 0.7', $compiled );
		} finally {
			$settings->replace( $snapshot );
			Plugin::instance()->compiled()->rebuild();
		}
	}
}
