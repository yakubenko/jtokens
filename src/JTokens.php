<?php
namespace Yakubenko\JTokens;

use Exception;

class JTokens
{
    private $secretKey;
    private $algorythm;
    private $type;

    private $payload = [];
    private $urlSafe = true;

    /**
     * @var Enum\ExpireModes
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
     * @param Enum\AlgorythmTypes|null $algorythm Algorythm
     * @param Enum\SupportedTypes|null $type Type
     * @param Enum\ExpireModes|null $expireMode Expire mode
     */
    public function __construct(
        ?Enum\AlgorythmTypes $algorythm = null,
        ?Enum\SupportedTypes $type = null,
        ?Enum\ExpireModes $expireMode = null
    ) {
        $this->algorythm = $algorythm ?? Enum\AlgorythmTypes::HS256();
        $this->type = $type ?? Enum\SupportedTypes::JWT();
        $this->expireMode = $expireMode ?? Enum\ExpireModes::LOW();
    }

    /**
     * Makes a JWT token URL safe by replacing symbols / and +
     *
     * @param bool $safe safety flag
     * @return self
     */
    public function setUrlSafe(bool $safe) :self
    {
        $this->urlSafe = $safe;

        return $this;
    }

    /**
     * Sets the secret key
     *
     * @param string $key The key
     * @return self
     */
    public function setKey(string $key) :self
    {
        $this->secretKey = $key;

        return $this;
    }

    /**
     * Sets the payload data for the token
     *
     * @param array $payload Array of the payload data
     * @return self
     */
    public function setPayload(array $payload = []) :self
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
    private function makeHeader()
    {
        $algorythm = array_flip(Enum\AlgorythmTypes::toArray())[(string)$this->algorythm];

        $data = [
            'alg' => $algorythm,
            'typ' => $this->type
        ];

        $json = json_encode($data);

        return $this->encode64($json);
    }

    /**
     * Sets expires mode
     *
     * @param Enum\ExpireModes|null $mode Sets one of predefined modes (strict|middle|low)
     * @return self
     */
    public function setExpireMode(?Enum\ExpireModes $mode) :self
    {
        $this->expireMode = $mode;

        return $this;
    }

    /**
     * Sets $this->expires based on the value of
     * $period
     *
     * @param string $period A period in Human readable format. Ex.: "+ 10 minutes" or "+ 2 hours" etc.
     * @return self
     */
    public function setExpiresTsHr($period) :self
    {
        if (!is_numeric($period)) {
            throw new Exception('Wrong value for a timestamp');
        }

        $this->expiresTs = strtotime($period, time());

        return $this;
    }

    /**
     * Returns a string which represents a timestamp when
     * the token must be invalidated. The returning value is based on
     * the value of $this->expireMode
     *
     * @return string A timestamp value
     */
    private function getExpires()
    {
        if (!is_null($this->expiresTs) && is_numeric($this->expiresTs)) {
            return $this->expiresTs;
        }

        // This is quite a long period. So, lets think that the token never expires
        $expires = strtotime("+ 10 years", time());

        switch ($this->expireMode) {
            case Enum\ExpireModes::STRICT():
                $expires = strtotime("+ 1 day", time());
                break;

            case Enum\ExpireModes::MIDDLE():
                $expires = strtotime("+ 1 week", time());
                break;
            case Enum\ExpireModes::LOW():
                $expires = strtotime("+ 1 month", time());
                break;
        }

        return $expires;
    }

    /**
     * Encodes payload
     *
     * @return string
     */
    private function makePayload()
    {
        $exp = $this->getExpires();
        $json = json_encode(array_merge($this->payload, compact('exp')));

        return $this->encode64($json);
    }

    /**
     * Creates a JWT token
     *
     * @return string
     */
    public function makeToken()
    {
        if (empty($this->secretKey)) {
            throw new Exception('The secret key is empty. Can not make a token');
        }

        $header = $this->makeHeader();
        $payload = $this->makePayload();
        $hash = hash_hmac($this->getAlgorythm(), $header . '.' . $payload, $this->secretKey, true);
        $signature = $this->encode64($hash);

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * Splits a token and checks that all its parts are valid
     *
     * @param string $token a JWT token
     * @return array
     * @throws Exception
     */
    public static function splitToken($token)
    {
        $parts = explode(".", trim($token));

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
    public static function getTokenPayload($token)
    {
        $parts = self::splitToken($token);
        $payload = base64_decode(self::base64Compat($parts[1]));
        $payload = json_decode($payload, true);

        if (!is_array($payload)) {
            throw new Exception(__('Wrong token format'));
        }

        return $payload;
    }

    /**
     * Validates provided token using provided $key
     *
     * @param string $token A JWT token
     * @param string $key a key that was used to encrypt the token
     * @return bool
     */
    public static function validateToken($token, $key, ?Enum\AlgorythmTypes $algorythm = null)
    {
        $parts = self::splitToken($token);
        $header = $parts[0];
        $payload = $parts[1];

        $algorythm = $algorythm ?? Enum\AlgorythmTypes::HS256();
        $signature = base64_encode(hash_hmac($algorythm, $header . '.' . $payload, $key, true));

        if (!empty($payload['exp']) && $payload['exp'] <= time()) {
            return false;
        }

        return hash_equals(self::base64Compat($parts[2]), $signature);
    }

    /**
     * Generates a hash which can be used for different purposes
     *
     * @param string $prefix Concat the hash with this prefix
     * @param int $numBytes The number of random bytes
     * @param Enum\SupportedTypes|null $algo The algo that this method will use to generate a hash
     * @return string
     */
    public static function generateHash($prefix = '', $numBytes = 10000, ?Enum\SupportedTypes $algo = null)
    {
        $algo = $algo ?? Enum\SupportedTypes::HS256();

        return $prefix . hash($algo, openssl_random_pseudo_bytes($numBytes) . openssl_random_pseudo_bytes($numBytes));
    }

    /**
     * Rebuilds a URL compatible base64_encoded string into a native one
     *
     * @param string $encString base64url_encoded string
     * @return string
     */
    public static function base64Compat(String $encString)
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
    public static function base64UrlSafe(String $encString)
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
    private function encode64(String $str)
    {
        return ($this->urlSafe) ? self::base64UrlSafe(base64_encode($str)) : base64_encode($str);
    }

    /**
     * Returns the algo of current instance
     *
     * @return Enum\AlgorythmTypes
     */
    public function getAlgorythm() :Enum\AlgorythmTypes
    {
        return $this->algorythm;
    }
}