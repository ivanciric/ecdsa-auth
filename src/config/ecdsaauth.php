<?php

return [
    /*
    |--------------------------------------------------------------------------
    | User Provider
    |--------------------------------------------------------------------------
    |
    | User class that should be used when attempting to
    | authenticate an incoming API request.
    |
    */
    'user_provider' => \App\User::class,

    /*
    |--------------------------------------------------------------------------
    | Lookup Field
    |--------------------------------------------------------------------------
    |
    | Field that should be initially checked when attempting to
    | authenticate an incoming API request.
    | This field is included in the payload and is the main method for finding
    | a user in the database.
    |
    */
    'lookup_field' => 'email',

    /*
    |--------------------------------------------------------------------------
    | Verification
    |--------------------------------------------------------------------------
    |
    | User in your app can be verified or not (active or inactive).
    | You can enable this option and set the verified_field
    | and verified_pass_condition parameters to match against.
    |
    */
    'verification' => false,

    /*
    |--------------------------------------------------------------------------
    | Verified Field
    |--------------------------------------------------------------------------
    |
    | Field that should be checked for verification condition.
    | This could be anything that marks the user as active, e.g. verified_email.
    |
    */
    'verified_field' => 'email_verified',

    /*
    |--------------------------------------------------------------------------
    | Verified Pass Condition
    |--------------------------------------------------------------------------
    |
    | Condition which should be checked upon the verified_field.
    |
    */
    'verified_pass_condition' => 1,

    /*
    |--------------------------------------------------------------------------
    | Key Lookup Field
    |--------------------------------------------------------------------------
    |
    | Field that contains the public key/address of the user.
    |
    */
    'key_lookup_field' => 'crypto_key',

    /*
    |--------------------------------------------------------------------------
    | Authorization Header
    |--------------------------------------------------------------------------
    |
    | Which header will be used as data vessel.
    |
    */
    'authorization_header' => 'authorization',

    /*
    |--------------------------------------------------------------------------
    | Authorization Methods
    |--------------------------------------------------------------------------
    |
    | Which header method will designate the payload.
    | Encryption type is based on this method.
    | Currently supported: Eth, Ecdsa
    |
    */
    'authorization_methods' => [
        'eth',
        'ecdsa',
    ],

    /*
    |--------------------------------------------------------------------------
    | Message Property
    |--------------------------------------------------------------------------
    |
    | Property name within the payload, which contains the message.
    |
    */
    'message_property' => 'message',

    /*
    |--------------------------------------------------------------------------
    | Signature Property
    |--------------------------------------------------------------------------
    |
    | Property name within the payload, which contains the signature.
    |
    */
    'signature_property' => 'signature',

    /*
    |--------------------------------------------------------------------------
    | Error Messages
    |--------------------------------------------------------------------------
    |
    | Feel free to define your error messages below.
    |
    */
    'error_messages' => [

        'invalid_auth_header' => 'Invalid authentication header.',

        'hash_already_used' => 'Hash already used.',

        'user_not_found' => 'User not found.',

        'user_not_verified' => 'User not verified.',

        'invalid_auth_data' => 'Invalid authentication data.',

        'invalid_signature' => 'Invalid signature',

        'method_not_allowed' => 'Authorization method not allowed',

        'crypto_failure' => 'Cryptographic provider failure.',

        'address_extraction_failure' => 'Could not extract address from public key.',

        'keccak_hash_failure' => 'Keccak hash failure.',

        'pub_key_failure' => 'Public key recovery failure.',

    ],
];
