<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Config;

use Amtgard\IdP\Utility\PubSubQueueHandle;
use Amtgard\SetQueue\DataStructure\SetQueue;
use Amtgard\SetQueue\PubSubQueue;
use PHPUnit\Framework\TestCase;

/**
 * Mirrors config/container.php PubSubQueueHandle wiring for redis-set-queue v1.1.x.
 */
class PubSubQueueHandleWiringTest extends TestCase
{
    public function testAddQueueRegistersQueueByName(): void
    {
        $queueName = 'amtgard-idp';
        $queue = $this->createMock(SetQueue::class);
        $pubSub = $this->createMock(PubSubQueue::class);

        $pubSub->expects($this->once())
            ->method('addQueue')
            ->with($queueName, $queue)
            ->willReturn($queueName);

        $pubSub->addQueue($queueName, $queue);

        $handle = PubSubQueueHandle::builder()->handle($queueName)->build();

        $this->assertSame($queueName, $handle->getHandle());
    }
}
