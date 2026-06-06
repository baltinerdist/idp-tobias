<?php
declare(strict_types=1);

namespace Amtgard\IdP\Utility\Exception;

use RuntimeException;
use Throwable;

class MalformedUserPolicyException extends RuntimeException
{
    public const USER_MESSAGE = 'Your user has a malformed IDP Access Policy. Contact admin for help.';

    public function __construct(?Throwable $previous = null)
    {
        parent::__construct(self::USER_MESSAGE, 0, $previous);
    }
}
