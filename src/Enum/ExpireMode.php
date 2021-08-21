<?php
declare(strict_types=1);

namespace Yakubenko\JTokens\Enum;

use MyCLabs\Enum\Enum;

/**
 * @psalm-immutable
 * @method static self LOW()
 * @method static self MIDDLE()
 * @method static self STRICT()
 */
final class ExpireMode extends Enum
{
    private const LOW = 'low';
    private const MIDDLE = 'middle';
    private const STRICT = 'strict';
}
