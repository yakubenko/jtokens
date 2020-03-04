<?php
namespace Yakubenko\JTokens\Enum;

use MyCLabs\Enum\Enum;

/**
 * @method static self HS256()
 * @method static self HS384()
 * @method static self HS512()
 */
final class AlgorythmTypes extends Enum
{
    private const HS256 = 'sha256';
    private const HS384 = 'sha384';
    private const HS512 = 'sha512';
}
