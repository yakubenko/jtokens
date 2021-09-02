<?php
declare(strict_types=1);

namespace Yakubenko\JTokens;

use Exception;
use Yakubenko\JTokens\Interface\KeyInterface;

class JTokens
{
    private $secretKey;
    private Enum\AlgorithmType $algorithm;
    private Enum\SupportedType $type;

    private array $payload = [];
    private bool $urlSafe = true;

    /**
     * @var Enum\ExpireMode|null
     * */
    private $expireMode;

    /**
     * this prop is used to generate expires payload when not null.
     * Probably will be used as default flag in next versions
     *
     * @var int|null
     */
    private $expiresTs;

    /**
     * Initialize the token object
     *
     * @param Enum\AlgorithmType|null $algorithm Algorithm
     * @param Enum\SupportedType|null $type Type
     * @param Enum\ExpireMode|null $expireMode Expire mode
     */
    public function __construct(
        ?Enum\AlgorithmType $algorithm = null,
        ?Enum\SupportedType $type = null,
        ?Enum\ExpireMode $expireMode = null
    ) {
        $this->algorithm = $algorithm ?? Enum\AlgorithmType::HS256();
        $this->type = $type ?? Enum\SupportedType::JWT();
        $this->expireMode = $expireMode ?? Enum\ExpireMode::LOW();
    }

    /**
     * Makes a JWT token URL safe by replacing symbols / and +
     *
     * @param bool $safe safety flag
     * @return self
     */
    public function setUrlSafe(bool $safe): self
    {
        $this->urlSafe = $safe;

        return $this;
    }

    /**
     * Sets the secret key
     *
     * @param mixed $key The key
     * @return self
     */
    public function setSecretKey($key): self
    {
        /**
         * Will be removed after php 8 migration
         * and using union types
         */
        if (!is_string($key) && !$key instanceof KeyInterface) {
            throw new Exception('Wrong key type');
        }

        $this->secretKey = $key;

        return $this;
    }

    /**
     * Sets the payload data for the token
     *
     * @param array $payload Array of the payload data
     * @return self
     */
    public function setPayload(array $payload = []): self
    {
        $this->payload = $payload;

        return $this;
    }

    /**
     * Encrypts the header of our JWT.
     * For now it only returns very basic header such as
     * {"alg": "HS256", "typ": "JWT"}
     *
     * @return string
     */
    private function makeHeader(): string
    {
        $algorithm = array_flip(
            Enum\AlgorithmType::toArray()
        )[$this->algorithm->getValue()];

        $data = [
            'alg' => $algorithm,
            'typ' => $this->type,
        ];

        $json = json_encode($data);

        return $this->encode64($json);
    }

    /**
     * Sets expires mode
     *
     * @param Enum\ExpireMode|null $mode Sets one of predefined modes (strict|middle|low)
     * @return self
     */
    public function setExpireMode(?Enum\ExpireMode $mode): self
    {
        $this->expireMode = $mode;

        return $this;
    }

    /**
     * Sets $this->expires based on the value of
     * $period
     *
     * @see strtotime()
     * @param string $period Ex.: "+ 10 minutes" or "+ 2 hours" etc.
     * @return self
     */
    public function setExpiresPeriod(string $period): self
    {
        $expiresTs = strtotime($period);

        if (!$expiresTs) {
            throw new Exception('Wrong time string');
        }

        $this->expiresTs = $expiresTs;

        return $this;
    }

    /**
     * Manually sets the expires ts
     *
     * @param int $ts Timestamp
     * @return self
     */
    public function setExpiresTs(int $ts): self
    {
        $this->expiresTs = $ts;

        return $this;
    }

    /**
     * Returns a string which represents a timestamp when
     * the token must be invalidated. The returning value is based on
     * the value of $this->expireMode
     *
     * @return int A timestamp value
     */
    public function getExpires(): int
    {
        if (!is_null($this->expiresTs)) {
            return $this->expiresTs;
        }

        // This is quite a long period. So, lets think that the token never expires
        $expires = strtotime('+ 10 years');

        switch ($this->expireMode) {
            case Enum\ExpireMode::STRICT():
                $expires = strtotime('+ 1 day');
                break;

            case Enum\ExpireMode::MIDDLE():
                $expires = strtotime('+ 1 week');
                break;
            case Enum\ExpireMode::LOW():
            default:
                $expires = strtotime('+ 1 month');
                break;
        }

        return $expires;
    }

    /**
     * Encodes payload
     *
     * @return string
     */
    private function makePayload(): string
    {
        $exp = $this->getExpires();

        if ($this->secretKey instanceof KeyInterface) {
            $this->payload['key_id'] = $this->secretKey->getId();
        }

        $json = json_encode(array_merge($this->payload, compact('exp')));

        return $this->encode64($json);
    }

    /**
     * Creates a JWT token
     *
     * @return string
     */
    public function makeToken(): string
    {
        if (!$this->secretKey) {
            throw new Exception(
                'The secret key is empty. Can not make a token.'
            );
        }

        $header = $this->makeHeader();
        $payload = $this->makePayload();
        $secretKey = $this->secretKey instanceof KeyInterface
        ? $this->secretKey->getStringValue()
        : $this->secretKey;

        $hash = hash_hmac(
            $this->getAlgorithm()->getValue(),
            $header . '.' . $payload,
            $secretKey,
            true
        );

        $signature = $this->encode64($hash);

        return sprintf(
            '%s.%s.%s',
            $header,
            $payload,
            $signature
        );
    }

    /**
     * Splits a token and checks that all its parts are valid
     *
     * @param string $token a JWT token
     * @return array
     * @throws Exception
     */
    public static function splitToken(string $token): array
    {
        $parts = explode('.', trim($token));

        /**
         * @TODO: add regex check if a part is base64 encoded
         * ^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$
         * https://stackoverflow.com/questions/8571501/how-to-check-whether-a-string-is-base64-encoded-or-not
        */
        if (count($parts) !== 3) {
            throw new Exception('Wrong token format');
        }

        return $parts;
    }

    /**
     * Returns token's payload without validating it
     *
     * @param string $token A JWT token
     * @return array
     */
    public static function getTokenPayload(string $token): array
    {
        $parts = self::splitToken($token);
        $payload = base64_decode(self::base64Compat($parts[1]));
        $payload = json_decode($payload, true);

        if (!is_array($payload)) {
            throw new Exception('Wrong token format');
        }

        return $payload;
    }

    /**
     * Validates provided token using provided $key
     *
     * @param string $token A JWT token
     * @param string $key a key that was used to encrypt the token
     * @param Enum\AlgorithmType|null $algorithm algo
     * @param Interface\KeysStorageInterface $keysStorage Keys storage
     * @return bool
     */
    public static function validateToken(
        string $token,
        ?string $key = null,
        ?Enum\AlgorithmType $algorithm = null,
        ?Interface\KeysStorageInterface $keysStorage = null
    ): bool {
        [$header, $payload, $signature] = self::splitToken($token);
        $payloadDecoded = self::getTokenPayload($token);
        $keyId = $payloadDecoded['key_id'] ?? null;

        if ($keyId && !$keysStorage) {
            throw new Exception(
                sprintf(
                    'No Keys storage (%s) provided',
                    Interface\KeysStorageInterface::class
                )
            );
        }

        if ($keysStorage && !$keyId) {
            throw new Exception(
                'Key identifier is not in the payload'
            );
        }

        if ($keysStorage) {
            try {
                $key = $keysStorage->getKeyById($keyId);
            } catch (Exception $e) {
                return false;
            }
        }

        // Check the key level
        if (
            $key instanceof KeyInterface &&
            ($key->isRevoked() || $key->isExpired())
        ) {
            return false;
        }

        if (!empty($payloadDecoded['exp']) && $payloadDecoded['exp'] <= time()) {
            return false;
        }

        // Get the actual Key value
        $keyStrValue = $key instanceof KeyInterface
        ? $key->getStringValue()
        : $key;

        if (!$keyStrValue) {
            return false;
        }

        $algorithm = $algorithm ?? Enum\AlgorithmType::HS256();
        $signatureCheck = base64_encode(
            hash_hmac(
                $algorithm->getValue(),
                $header . '.' . $payload,
                $keyStrValue,
                true
            )
        );

        return hash_equals(self::base64Compat($signature), $signatureCheck);
    }

    /**
     * Generates a hash which can be used for different purposes
     *
     * @param int $numBytes The number of random bytes
     * @param string $prefix Concat the hash with this prefix
     * @param Enum\SupportedType|null $algo The algo that will be used
     * @return string
     */
    public static function generateHash(
        int $numBytes = 10000,
        string $prefix = '',
        ?Enum\SupportedType $algo = null
    ): string {
        $algo = $algo ?? Enum\SupportedType::HS256();

        return $prefix . hash(
            (string)$algo,
            openssl_random_pseudo_bytes($numBytes) .
            openssl_random_pseudo_bytes($numBytes)
        );
    }

    /**
     * Rebuilds a URL compatible base64_encoded string into a native one
     *
     * @param string $encString base64url_encoded string
     * @return string
     */
    public static function base64Compat(string $encString): string
    {
        $encString = str_replace('=', '', $encString);
        $encString = str_replace(['-', '_'], ['+', '/'], $encString);

        switch (strlen($encString) % 4) {
            case 0:
                break;
            case 2:
                $encString .= '==';
                break;
            case 3:
                $encString .= '=';
                break;
            default:
                throw new Exception('The string is not Base64 encoded');
        }

        return $encString;
    }

    /**
     * Makes a base64_encoded string URL safe
     *
     * @param string $encString base64_encoded string
     * @return string
     */
    public static function base64UrlSafe(string $encString): string
    {
        $encString = str_replace('=', '', $encString);
        $encString = str_replace(['+', '/'], ['-', '_'], $encString);

        return $encString;
    }

    /**
     * Encodes into a base64 string based on URL safety flag
     *
     * @param string $str string to encode
     * @return string
     */
    private function encode64(string $str): string
    {
        return ($this->urlSafe)
        ? self::base64UrlSafe(base64_encode($str))
        : base64_encode($str);
    }

    /**
     * Returns the algo of current instance
     *
     * @return Enum\AlgorithmType
     */
    public function getAlgorithm(): Enum\AlgorithmType
    {
        return $this->algorithm;
    }

    /**
     * Sets an algo
     *
     * @param Enum\AlgorithmType $algorithm algorithm
     * @return self
     */
    public function setAlgorithm(Enum\AlgorithmType $algorithm): self
    {
        $this->algorithm = $algorithm;

        return $this;
    }
}
