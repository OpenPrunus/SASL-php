# SASL-php

This library is a Simple Authentication and Security Layer php library.

## /!\ Support for PLAIN actually. Work in progress for others

For add a dependency composer in your project :

```
$composer require OpenPrunus/sasl-php
```

## Usage

```php
$factory = new Factory("plain");

$arguments = [
    'authzid' => 'id',
    'authcid' => 'username',
    'passwd'  => 'mypassword'
];

$plainResponse = $factory->getFormattedResponse($arguments);
```
