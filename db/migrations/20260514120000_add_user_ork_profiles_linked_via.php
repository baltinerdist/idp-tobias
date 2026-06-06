<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class AddUserOrkProfilesLinkedVia extends AbstractMigration
{
    public function change(): void
    {
        $this->table('user_ork_profiles')
            ->addColumn('linked_via', 'enum', [
                'values' => ['self_form', 'ork_handoff', 'mirror'],
                'default' => 'self_form',
                'after' => 'user_id',
            ])
            ->update();
    }
}
