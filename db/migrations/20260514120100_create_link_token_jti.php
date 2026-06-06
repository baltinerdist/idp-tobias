<?php

declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateLinkTokenJti extends AbstractMigration
{
    public function change(): void
    {
        $this->table('link_token_jti', ['id' => false, 'primary_key' => ['jti']])
            ->addColumn('jti', 'string', ['limit' => 64])
            ->addColumn('seen_at', 'datetime', ['default' => 'CURRENT_TIMESTAMP'])
            ->addIndex(['seen_at'])
            ->create();
    }
}
