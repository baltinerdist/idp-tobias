<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * The OAuth server lookups scopes from the `scopes` table by scope_id. The
 * email/profile scopes the ORK client requests need to exist there or the
 * /oauth/authorize call rejects with "invalid scope". Idempotent.
 */
final class SeedOauthScopes extends AbstractMigration
{
    public function up(): void
    {
        $existing = $this->fetchAll('SELECT scope_id FROM scopes');
        $haveIds = array_map(fn($r) => $r['scope_id'], $existing);
        foreach (['email', 'profile'] as $scope) {
            if (!in_array($scope, $haveIds, true)) {
                // Parameterized insert (no raw string interpolation) so this stays
                // injection-safe if the scope list is ever sourced dynamically.
                $this->table('scopes')->insert(['scope_id' => $scope])->saveData();
            }
        }
    }

    public function down(): void
    {
        $this->execute("DELETE FROM scopes WHERE scope_id IN ('email','profile')");
    }
}
