<?php
declare(strict_types=1);

namespace Yakubenko\JTokens\Interface;

interface KeysStorageInterface
{
    /**
     * Returns a key object
     *
     * @param string $keyId Key ID
     * @return KeyInterface
     */
    public function getKeyById(string $keyId): KeyInterface;
}
