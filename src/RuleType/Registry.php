<?php
/**
 * The rule type registry.
 *
 * @package Kanopi\BasicFirewall
 */

declare( strict_types = 1 );

namespace Kanopi\BasicFirewall\RuleType;

use Kanopi\BasicFirewall\RuleType\Types\Abuse_Ipdb;
use Kanopi\BasicFirewall\RuleType\Types\Asn;
use Kanopi\BasicFirewall\RuleType\Types\Crs;
use Kanopi\BasicFirewall\RuleType\Types\Geo_Location;
use Kanopi\BasicFirewall\RuleType\Types\Ip_Address;
use Kanopi\BasicFirewall\RuleType\Types\Rate_Limit;
use Kanopi\BasicFirewall\RuleType\Types\Url;
use Kanopi\BasicFirewall\RuleType\Types\User_Agent;
use Kanopi\BasicFirewall\RuleType\Types\Vulnerability_Score;

/**
 * Holds the rule types, shipped and contributed.
 *
 * Drupal discovers these by scanning for a PHP attribute. WordPress has no
 * discovery at all, so the shipped types are listed and everyone else's arrive
 * through a filter.
 */
final class Registry {

	/**
	 * Resolved types, keyed by id.
	 *
	 * @var array<string, Rule_Type>|null
	 */
	private ?array $types = null;

	/**
	 * Every registered type, in chooser order.
	 *
	 * @return array<string, Rule_Type>
	 */
	public function all(): array {
		if ( null !== $this->types ) {
			return $this->types;
		}

		$types = array();

		foreach ( $this->shipped() as $type ) {
			$types[ $type->id() ] = $type;
		}

		/**
		 * Filters the registered firewall rule types.
		 *
		 * Add a type by adding an object implementing Rule_Type, keyed by its
		 * id. Removing one is also legitimate -- a site that must not offer
		 * geolocation can unset it here and the screen 404s accordingly.
		 *
		 * A contributed type cannot take the id of a shipped one: the shipped
		 * type is restored and the collision is recorded, matching the module's
		 * behaviour for a preset name collision. Silently replacing a shipped
		 * type would let a plugin change what an existing rule compiles to
		 * without anything in the interface changing.
		 *
		 * @param array<string, Rule_Type> $types Registered types, keyed by id.
		 */
		$filtered = apply_filters( 'basic_firewall_rule_types', $types );

		$resolved = array();

		if ( is_array( $filtered ) ) {
			foreach ( $filtered as $id => $type ) {
				if ( ! $type instanceof Rule_Type ) {
					continue;
				}

				$resolved[ (string) $id ] = $type;
			}
		}

		// Shipped types win a collision.
		foreach ( $this->shipped() as $type ) {
			if ( isset( $resolved[ $type->id() ] ) && $resolved[ $type->id() ] !== $type ) {
				$resolved[ $type->id() ] = $type;
			}
		}

		uasort(
			$resolved,
			static fn ( Rule_Type $a, Rule_Type $b ): int => array( $a->weight(), $a->label() ) <=> array( $b->weight(), $b->label() )
		);

		$this->types = $resolved;

		return $this->types;
	}

	/**
	 * The types this plugin ships.
	 *
	 * @return list<Rule_Type>
	 */
	private function shipped(): array {
		return array(
			new Ip_Address(),
			new User_Agent(),
			new Url(),
			new Rate_Limit(),
			new Asn(),
			new Geo_Location(),
			new Vulnerability_Score(),
			new Abuse_Ipdb(),
			new Crs(),
		);
	}

	/**
	 * The ids of the types this plugin ships.
	 *
	 * Used by the rule type chooser to say where each one came from. A type
	 * contributed through the filter compiles into the same firewall as a
	 * shipped one, so somebody deciding whether to trust it should not have to
	 * work that out for themselves.
	 *
	 * @return list<string>
	 */
	public function shipped_ids(): array {
		$ids = array();

		foreach ( $this->shipped() as $type ) {
			$ids[] = $type->id();
		}

		return $ids;
	}

	/**
	 * Only the types the installed library can actually provide.
	 *
	 * @return array<string, Rule_Type>
	 */
	public function available(): array {
		return array_filter( $this->all(), static fn ( Rule_Type $t ): bool => $t->is_available() );
	}

	/**
	 * One type by id, or null.
	 *
	 * @param string $id Type id.
	 */
	public function get( string $id ): ?Rule_Type {
		return $this->all()[ $id ] ?? null;
	}

	/**
	 * Whether a type is registered.
	 *
	 * @param string $id Type id.
	 */
	public function has( string $id ): bool {
		return null !== $this->get( $id );
	}

	/**
	 * Forget resolved types. Test seam.
	 *
	 * @internal
	 */
	public function reset(): void {
		$this->types = null;
	}
}
