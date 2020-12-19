JTokens - A Very basic implementation of JWT for php

## Installation

```
composer require yakubenko/jtokens
```

## Usage

### Make a token
```php
<?php

use Yakubenko\JTokens\JTokens;

$jtoken = new JTokens();
$jtoken->setSecretKey('key');
$jtoken->setPayload([
    'some' => 'value'
]);
$token = $jtoken->makeToken();
```

### Validate a token

```php
<?php

use Yakubenko\JTokens\JTokens;

$isTokenValid = JTokens::validateToken(
    $yourToken,
    $yourSecretKey
);
```
