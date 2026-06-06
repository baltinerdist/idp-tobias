<?php
declare(strict_types=1);

namespace Amtgard\IdP\Models;

/**
 * Value object wrapping the env-driven allow-list of confidential client_ids
 * permitted to call POST /resources/link-ork-profile.
 *
 * Encapsulating the parse here keeps the container free of bespoke wiring:
 * the object is autowireable (it reads LINK_ORK_PROFILE_ALLOWED_CLIENT_IDS
 * itself) so ConfidentialClientBasicAuthMiddleware can rely on automatic DI.
 */
class AllowedLinkOrkProfileClientIds
{
    /** @var string[] */
    private array $clientIds;

    public function __construct()
    {
        $list = (string) ($_ENV['LINK_ORK_PROFILE_ALLOWED_CLIENT_IDS'] ?? '');
        $this->clientIds = array_values(array_filter(array_map('trim', explode(',', $list))));
    }

    public function contains(string $clientId): bool
    {
        return in_array($clientId, $this->clientIds, true);
    }

    /** @return string[] */
    public function all(): array
    {
        return $this->clientIds;
    }
}
