<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

/**
 * Add UNIQUE indexes on user_ork_profiles.user_id and .mundane_id to close
 * the TOCTOU race in linkExistingUserToMundane (finding H3). With the unique
 * index in place, the repository can let the DB enforce idempotency and
 * convert duplicate-key violations into the no-op / conflict branches.
 *
 * The up() step first deduplicates any existing rows that would otherwise
 * block the unique index creation. Dedupe rule: keep the row with the
 * largest id per (user_id) and per (mundane_id), drop the rest. We rely
 * on `id` only — not `updated_at` — so older schemas without that column
 * still migrate cleanly. The largest id is a reasonable proxy for "newest"
 * since ids are monotonically increasing per AUTO_INCREMENT.
 */
final class AddUserOrkProfilesUniqueIndexes extends AbstractMigration
{
    public function up(): void
    {
        // Dedupe by user_id — keep the row with the largest id; drop older rows.
        $this->execute(<<<SQL
DELETE p1 FROM user_ork_profiles p1
INNER JOIN user_ork_profiles p2
    ON p1.user_id = p2.user_id
   AND p1.id < p2.id
SQL);

        // Dedupe by mundane_id — same rule.
        $this->execute(<<<SQL
DELETE p1 FROM user_ork_profiles p1
INNER JOIN user_ork_profiles p2
    ON p1.mundane_id = p2.mundane_id
   AND p1.mundane_id IS NOT NULL
   AND p2.mundane_id IS NOT NULL
   AND p1.id < p2.id
SQL);

        $this->table('user_ork_profiles')
            ->addIndex(['user_id'], ['unique' => true, 'name' => 'ux_user_ork_profiles_user_id'])
            ->addIndex(['mundane_id'], ['unique' => true, 'name' => 'ux_user_ork_profiles_mundane_id'])
            ->update();
    }

    public function down(): void
    {
        $this->table('user_ork_profiles')
            ->removeIndexByName('ux_user_ork_profiles_user_id')
            ->removeIndexByName('ux_user_ork_profiles_mundane_id')
            ->update();
    }
}
