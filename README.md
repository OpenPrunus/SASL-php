# sasl-php

A Simple Authentication and Security Layer PHP 7.2 library

## /!\ Support for PLAIN and SCRAM actually. Work in progress for others /!\

## Supported mechanisms

* PLAIN
* SCRAM


## For add a dependency composer in your project

```
$composer require openprunus/sasl-php
```

## Usage

```php
use SASL\Factory;
use SASL\Exceptions\FactoryException;
use SASL\Exceptions\MechanismsException;

try{
    $factory = new Factory("plain");
} catch (FactoryException $e) {
    echo $e->getMessage();
} catch (MechanismsException $e) {
    echo $e->getMessage();
}

$arguments = [
    'authzid' => 'id',
    'authcid' => 'username',
    'passwd'  => 'mypassword'
];

try {
    $plainResponse = $factory->getFormattedResponse($arguments);
} catch (MechanismsException $e) {
    echo $e->getMessage();
}

echo $plainResponse;
```

## Builds

- https://jenkins.ecuri.es/job/sasl-php
