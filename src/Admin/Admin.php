<?php
/**
 * Registers the administrative screens.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Admin;

use Kanopi\BasicFirewall\Admin\Screen\Advanced_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Blocked_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Challenge_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Compiled_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Dashboard_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Export_Screen;
use Kanopi\BasicFirewall\Admin\Screen\General_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Import_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Log_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Logging_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Presets_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rebuild_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rule_Edit_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Rules_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Storage_Screen;
use Kanopi\BasicFirewall\Admin\Screen\Test_Screen;
use Kanopi\BasicFirewall\Install\Capabilities;

/**
 * The admin menu, and the screens hanging off it.
 *
 * The module has 24 routes. WordPress has no router, so the equivalent is a
 * menu of screens plus a `screen` query argument for the ones that are really
 * operations on a thing -- editing a rule, deleting it, previewing a preset,
 * confirming an unblock. Every one of those is capability-checked on entry and
 * nonce-checked on write, without exception.
 */
final class Admin {

	/**
	 * The top-level menu slug.
	 */
	public const MENU = 'basic-firewall';

	/**
	 * Resolved screens, keyed by slug.
	 *
	 * @var array<string, Screen>|null
	 */
	private static ?array $screens = null;

	/**
	 * Hook the admin up.
	 */
	public static function register(): void {
		add_action( 'admin_menu', array( self::class, 'add_menu' ) );
		add_action( 'admin_init', array( self::class, 'handle_submission' ) );
		add_action( 'admin_enqueue_scripts', array( self::class, 'enqueue' ) );
	}

	/**
	 * Every screen.
	 *
	 * @return array<string, Screen>
	 */
	public static function screens(): array {
		if ( null !== self::$screens ) {
			return self::$screens;
		}

		$screens = array(
			new Dashboard_Screen(),
			new Rules_Screen(),
			new Rule_Edit_Screen(),
			new General_Screen(),
			new Storage_Screen(),
			new Logging_Screen(),
			new Challenge_Screen(),
			new Presets_Screen(),
			new Advanced_Screen(),
			new Test_Screen(),
			new Compiled_Screen(),
			new Export_Screen(),
			new Import_Screen(),
			new Log_Screen(),
			new Blocked_Screen(),
			new Rebuild_Screen(),
		);

		self::$screens = array();

		foreach ( $screens as $screen ) {
			self::$screens[ $screen->slug() ] = $screen;
		}

		return self::$screens;
	}

	/**
	 * Build the menu.
	 */
	public static function add_menu(): void {
		$top = null;

		foreach ( self::screens() as $screen ) {
			if ( ! $screen->in_menu() ) {
				continue;
			}

			if ( null === $top ) {
				add_menu_page(
					$screen->page_title(),
					__( 'Firewall', 'basic-firewall' ),
					$screen->capability(),
					$screen->slug(),
					static fn() => self::render( $screen->slug() ),
					'dashicons-shield-alt',
					// Below Settings, above Tools. A security tool belongs where
					// somebody looks for security, not buried under Settings.
					80
				);

				$top = $screen->slug();
			} else {
				add_submenu_page(
					(string) $top,
					$screen->page_title(),
					$screen->menu_title(),
					$screen->capability(),
					$screen->slug(),
					static fn() => self::render( $screen->slug() )
				);
			}
		}

		/*
		 * Screens reached from a link rather than from the menu still need
		 * registering, or WordPress refuses to render them at all. Registered
		 * with a null parent so they do not appear in the menu.
		 */
		foreach ( self::screens() as $screen ) {
			if ( $screen->in_menu() ) {
				continue;
			}

			add_submenu_page(
				'',
				$screen->page_title(),
				$screen->page_title(),
				$screen->capability(),
				$screen->slug(),
				static fn() => self::render( $screen->slug() )
			);
		}
	}

	/**
	 * Render one screen.
	 *
	 * @param string $slug Screen slug.
	 */
	public static function render( string $slug ): void {
		$screen = self::screens()[ $slug ] ?? null;

		if ( null === $screen ) {
			wp_die( esc_html__( 'That firewall screen does not exist.', 'basic-firewall' ), 404 );
		}

		// Checked again here, not only at registration: add_submenu_page()'s
		// capability governs the menu, and a screen reached by URL must not
		// depend on the menu having been built.
		if ( ! current_user_can( $screen->capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to view this firewall screen.', 'basic-firewall' ), 403 );
		}

		echo '<div class="wrap basic-firewall">';

		printf( '<h1>%s</h1>', esc_html( $screen->page_title() ) );

		$intro = $screen->intro();

		if ( '' !== $intro ) {
			printf( '<p class="description" style="max-width:48rem">%s</p>', wp_kses_post( $intro ) );
		}

		Notices::render();

		$screen->render();

		echo '</div>';
	}

	/**
	 * Dispatch a form submission to its screen.
	 *
	 * Runs on admin_init rather than during rendering, so that a screen which
	 * changes something can redirect afterwards -- which is what stops a browser
	 * refresh re-submitting it.
	 */
	public static function handle_submission(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$slug = isset( $_REQUEST['page'] ) ? sanitize_key( wp_unslash( $_REQUEST['page'] ) ) : '';

		if ( '' === $slug ) {
			return;
		}

		$screen = self::screens()[ $slug ] ?? null;

		if ( null === $screen ) {
			return;
		}

		if ( ! current_user_can( $screen->capability() ) ) {
			return;
		}

		$screen->handle();
	}

	/**
	 * Load the admin stylesheet.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public static function enqueue( string $hook ): void {
		if ( false === strpos( $hook, self::MENU ) ) {
			return;
		}

		wp_enqueue_style(
			'basic-firewall-admin',
			BASIC_FIREWALL_URL . 'assets/admin.css',
			array(),
			BASIC_FIREWALL_VERSION
		);
	}

	/**
	 * URL of a firewall screen.
	 *
	 * @param string               $slug Screen slug.
	 * @param array<string, mixed> $args Extra query arguments.
	 */
	public static function url( string $slug, array $args = array() ): string {
		return add_query_arg(
			array_merge( array( 'page' => $slug ), $args ),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Whether the current user can configure the firewall.
	 */
	public static function can_manage(): bool {
		return Capabilities::can_manage();
	}
}
