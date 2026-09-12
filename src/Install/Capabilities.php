<?php
/**
 * The capability model.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\Install;

/**
 * Translates the module's three permissions into WordPress capabilities.
 *
 * The split is the module's and is worth keeping rather than collapsing into
 * `manage_options`, because the three answer different questions:
 *
 * | Capability                        | Lets someone                                  |
 * |-----------------------------------|-----------------------------------------------|
 * | `manage_basic_firewall`           | decide which traffic reaches the site         |
 * | `view_basic_firewall_reports`     | see the dashboard, the log and who is blocked |
 * | `unblock_basic_firewall_clients`  | release a blocked client                      |
 *
 * The second and third exist so that support staff can answer "why can't this
 * customer reach the site?" and act on the answer, without also being able to
 * rewrite the rule set. Granting `manage_options` instead would mean the only
 * way to let somebody unblock a client is to let them reconfigure the firewall,
 * which is how a support role becomes an administrator role.
 *
 * The module marks two of these `restrict access: true`. WordPress has no
 * equivalent flag, so the equivalent is that none of them are granted to any
 * role but `administrator` on activation, and the plugin never grants them
 * anywhere else.
 */
final class Capabilities {

	/**
	 * Configure rules, storage, logging and the challenge flow.
	 */
	public const MANAGE = 'manage_basic_firewall';

	/**
	 * View the dashboard, the log report and the blocked client list.
	 */
	public const VIEW_REPORTS = 'view_basic_firewall_reports';

	/**
	 * Remove clients from the block list.
	 */
	public const UNBLOCK = 'unblock_basic_firewall_clients';

	/**
	 * Every capability this plugin defines.
	 *
	 * @return list<string>
	 */
	public static function all(): array {
		return array( self::MANAGE, self::VIEW_REPORTS, self::UNBLOCK );
	}

	/**
	 * Grant every capability to the administrator role.
	 *
	 * Called on activation and again by the upgrade routines, because a
	 * capability added in a later release has to reach sites that are upgrading
	 * rather than only sites that are installing.
	 */
	public static function grant(): void {
		$role = get_role( 'administrator' );

		if ( null === $role ) {
			return;
		}

		foreach ( self::all() as $capability ) {
			$role->add_cap( $capability );
		}
	}

	/**
	 * Remove every capability from every role.
	 *
	 * Uninstall only, never deactivation. Deactivating a plugin is routinely
	 * done to test something, and a deactivate/reactivate cycle that silently
	 * stripped a custom support role of its capabilities would be a bug that
	 * only shows up later, in the middle of an incident.
	 */
	public static function revoke(): void {
		$roles = wp_roles();

		foreach ( array_keys( $roles->roles ) as $role_name ) {
			$role = get_role( $role_name );

			if ( null === $role ) {
				continue;
			}

			foreach ( self::all() as $capability ) {
				$role->remove_cap( $capability );
			}
		}
	}

	/**
	 * Whether the current user may configure the firewall.
	 */
	public static function can_manage(): bool {
		return current_user_can( self::MANAGE );
	}

	/**
	 * Whether the current user may read firewall reports.
	 *
	 * Managing implies reading. Someone who can rewrite the rules can already
	 * see everything the reports show, so requiring both capabilities would only
	 * produce administrators who cannot read their own dashboard.
	 */
	public static function can_view_reports(): bool {
		return current_user_can( self::VIEW_REPORTS ) || current_user_can( self::MANAGE );
	}

	/**
	 * Whether the current user may unblock a client.
	 */
	public static function can_unblock(): bool {
		return current_user_can( self::UNBLOCK ) || current_user_can( self::MANAGE );
	}
}
