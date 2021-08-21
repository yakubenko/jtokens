<?php
declare(strict_types=1);

namespace Yakubenko\JTokens\Enum;

use MyCLabs\Enum\Enum;

/**
 * @psalm-immutable
 * @method static self HS256()
 * @method static self HS384()
 * @method static self HS512()
 */
final class AlgorithmType extends Enum
{
    private const HS256 = 'sha256';
    private const HS384 = 'sha384';
    private const HS512 = 'sha512';
}
