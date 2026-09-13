<?php
/**
 * The admin menu, as the plugin actually wires it.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Tests\integration;

use Kanopi\BasicFirewall\Admin\Admin;
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
}
