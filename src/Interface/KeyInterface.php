<?php
declare(strict_types=1);

namespace Yakubenko\JTokens\Interface;

use DateTimeInterface;

interface KeyInterface
{
    /**
     * Get identifier
     *
     * @return mixed
     */
    public function getId(): mixed;

    /**
     * Get key expires date
     *
     * @return DateTimeInterface|null
     */
    public function getExpires(): ?DateTimeInterface;

    /**
     * Checks if the key is expired
     *
     * @return bool
     */
    public function isExpired(): bool;

    /**
     * Is revoked
     *
     * @return bool
     */
    public function isRevoked(): bool;

    /**
     * Get key's string value
     *
     * @return string
     */
    public function getStringValue(): string;
}
