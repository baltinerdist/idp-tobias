<?php
declare(strict_types=1);

namespace Amtgard\IdP\Tests\Utility\Exception;

use Amtgard\IdP\Utility\Exception\MalformedUserPolicyException;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class MalformedUserPolicyExceptionTest extends TestCase
{
    public function testUserMessageIsExposedAsConstant(): void
    {
        $this->assertSame(
            'Your user has a malformed IDP Access Policy. Contact admin for help.',
            MalformedUserPolicyException::USER_MESSAGE
        );
    }

    public function testWrapsPreviousThrowable(): void
    {
        $cause = new InvalidArgumentException('invalid ORN segment');
        $exception = new MalformedUserPolicyException($cause);

        $this->assertSame(MalformedUserPolicyException::USER_MESSAGE, $exception->getMessage());
        $this->assertSame($cause, $exception->getPrevious());
    }
}
