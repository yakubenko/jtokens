<?php
declare(strict_types=1);

namespace Yakubenko\JTokens\Enum;

use MyCLabs\Enum\Enum;

/**
 * @psalm-immutable
 * @method static self JWT()
 */
final class SupportedType extends Enum
{
    private const JWT = 'JWT';
}
