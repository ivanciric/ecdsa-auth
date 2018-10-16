# Ecdsa Auth
[ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) authentication for [Laravel](https://laravel.com)/[Dingo API](https://github.com/dingo/api)
based on [elliptic-php](https://github.com/simplito/elliptic-php) and [keccak](https://github.com/kornrunner/php-keccak) packages.

## Instalation
```$xslt
composer require ivanciric/ecdsa-auth
```

Library uses package auto-discovery feature, so you don't need to set the service provider manually. 

Publish the package configuration
```$xslt
php artisan vendor:publish --provider="ivanciric/EcdsaAuth/ServiceProvider"
```
## Configuration
After publishing configuration, you can edit the available options in __config/ecdsaauth.php__

| Option  | Details |
| -------------  | ------------- |
| user_provider  | User class that should be used when attempting to authenticate an incoming API request. Default: __\App\User::class__|
| lookup_field   | Field that should be initially checked when attempting to authenticate an incoming API request. Default: __email__ |
| verification | If you require users to be verified (e.g. email verified) in order to access the data, set this otion to true. Default: __false__ |
| verified_field | If you've set the verification to true, state the field which marks the user as verified. Default: __email_verified__ |
| verified_pass_condition | Value of the verified_field that marks the user as verified. Default: __1__ |
| key_lookup_field | Field which contains the public key of the user. This could be Ethereum address or pure Ecdsa public key. Default: __crypto_key__ |
| authorization_header | Name of the header which holds the authorization payload. Default: __authorization__ |
| authorization_methods | Methods allowed in the authorization header. They denote supported encryption algorithms. Default: __['eth', 'ecdsa']__ |
| message_property | Key in the payload which contains the message. Default: __message__ |
| signature_property | Key in the payload which contains the signature. Default: __signature__ |
| error_messages | Array of various friendly error messages. |

## Usage
This package presumes you have Dingo API setup.
Edit the __config/api.php__ file and set the __auth__ key as follows:
```$xslt
'auth' => [
        'ivanciric\EcdsaAuth\Authenticator'
 ]
```
You should set the __lookup_key__ and __key_lookup_field__ in the package config to reflect your user properties.

Protect your routes by specifying the middleware:
```$xslt
$api->version('v1', ['middleware' => 'api.auth'], function ($api) {
    ...
});
``` 

## Creating the payload
Authorization header should contain the payload in the following forms:
```$xslt
Eth eyJlbWFpbCI6ImhhQG1hLnRvIiwibWVzc2FnZSI6IjkyNThhNjQ0Y2FmZTZ...
```
or
```$xslt
Ecdsa eyJlbWFpbCI6ImhhQG1hLnRvIiwibWVzc2FnZSI6IjkyNThhNjQ0Y2FmZTZ...
```

Payload itself is a __base64__ encoded __json__ with the following properties:
```$xslt
{
    "email": "h@ma.to", // user's email or alternative lookup field
    "message": "9258a644cafe6af00...", // sha256 encoded string
    "signature": "3046022100a94c1a..." // signed message
}
```

All properties are configurable.