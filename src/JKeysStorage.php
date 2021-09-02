<?php
declare(strict_types=1);

namespace Yakubenko\JTokens;

use DateTimeImmutable;
use Exception;
use Yakubenko\JTokens\Interface\KeyInterface;
use Yakubenko\JTokens\Interface\KeysStorageInterface;

class JKeysStorage implements KeysStorageInterface
{
    private array $keys = [];

    /**
     * @param string $keysFilePath JsonKeys file path
     */
    public function __construct(
        private string $keysFilePath
    ) {
        $this->loadKeysFromFile($keysFilePath);
    }

    /**
     * @inheritDoc
     */
    public function getKeyById(string $keyId): KeyInterface
    {
        $key = $this->keys[$keyId] ?? null;

        if (!$key) {
            throw new Exception('Key not found');
        }

        $expires = $key['expires'] ?? null;

        $expires = $expires ?
        new DateTimeImmutable($expires)
        : null;

        return new JKey(
            $key['id'],
            $expires,
            $key['key'],
            $key['revoked']
        );
    }

    /**
     * Fill the keys array
     *
     * @param string $path File path
     * @return void
     */
    private function loadKeysFromFile(string $path): void
    {
        $fileContents = file_get_contents($path);
        $keysData = json_decode($fileContents, true);

        foreach ($keysData as $key) {
            if (!is_array($key) || !$this->validateKey($key)) {
                continue;
            }

            $this->keys[$key['id']] = $key;
        }
    }

    /**
     * Validates key's data
     *
     * @param array $keyData data
     * @return bool
     */
    private function validateKey(array $keyData): bool
    {
        $required = ['id', 'key', 'revoked'];

        $valid = (
            count(
                array_intersect_key(
                    array_flip($required),
                    $keyData
                )
            ) === count($required)
        );

        return $valid;
    }
}
