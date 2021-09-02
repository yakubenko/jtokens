<?php
declare(strict_types=1);

namespace Yakubenko\JTokens;

use DateTimeImmutable;
use DateTimeInterface;
use Yakubenko\JTokens\Interface\KeyInterface;

class JKey implements KeyInterface
{
    /**
     * @param string $id ID
     * @param null|DateTimeInterface $expires Expires DT
     * @param string $stringValue String value
     * @param bool $revoked Revoke flag
     */
    public function __construct(
        private string $id,
        private ?DateTimeInterface $expires,
        private string $stringValue,
        private bool $revoked = false
    ) {
    }

    /**
     * @inheritDoc
     */
    public function getId(): string
    {
        return $this->id;
    }

    /**
     * @inheritDoc
     */
    public function getExpires(): ?DateTimeInterface
    {
        return $this->expires;
    }

    /**
     * @inheritDoc
     */
    public function isExpired(): bool
    {
        if (is_null($this->expires)) {
            return false;
        }

        return new DateTimeImmutable() >= $this->expires;
    }

    /**
     * @inheritDoc
     */
    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    /**
     * @inheritDoc
     */
    public function getStringValue(): string
    {
        return $this->stringValue;
    }
}
