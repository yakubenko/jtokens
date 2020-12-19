<?php
namespace Yakubenko\JTokens\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static self LOW()
 * @method static self MIDDLE()
 * @method static self STRICT()
 */
final class ExpireModes extends Enum
{
    private const LOW = 'low';
    private const MIDDLE = 'middle';
    private const STRICT = 'strict';
}
