<?php

namespace ivanciric\EcdsaAuth;

use Elliptic\EC;
use kornrunner\Keccak;
use Illuminate\Http\Request;
use Dingo\Api\Routing\Route;
use Illuminate\Support\Facades\Log;
use Dingo\Api\Auth\Provider\Authorization;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;

/**
 * ECDSA Authorization for Laravel/Dingo API
 *
 * Class EcdsaAuth
 * @package App\Api\V1\Services\Auth
 */
class Authenticator extends Authorization
{
    /**
     * Eliptic Curve library.
     *
     * @var EC
     */
    public $elipticCurve;

    /**
     * DingoecdsaauthProvider constructor.
     */
    public function __construct()
    {
        $this->elipticCurve = new EC('secp256k1');
    }

    /**
     * Main authentication method.
     *
     * @param Request $request
     * @param Route $route
     * @return bool|mixed
     */
    public function authenticate(Request $request, Route $route)
    {
        try {
            $this->validateAuthorizationHeader($request);
        } catch (\Exception $e) {
            $this->handleError(
                $e->getMessage(),
                'invalid_auth_header'
            );
        }

        $authHash = $this->validateAuthorizationHash($request->headers->get(
            config(
                'ecdsaauth.authorization_header',
                'authorization'
            )
        ));

        $authData = $this->decodeAuthData(
            $request->headers->get(
                config(
                    'ecdsaauth.authorization_header',
                    'authorization'
                )
            )
        );

        $user = $this->checkUser(
            config(
                'ecdsaauth.lookup_field',
                'email'
            ),
            $authData
        );

        try {
            $valid = $this->{$this->verificationMethodName($request)}(
                $authData->{config('ecdsaauth.message_property', 'message')},
                $authData->{config('ecdsaauth.signature_property', 'signature')},
                $user->{config('ecdsaauth.key_lookup_field', 'crypto_key')}
            );

            if ($valid) {
                $this->invalidateHash($authHash);
                return $user;
            } else {
                $this->handleError(
                    config(
                        'ecdsaauth.error_messages.invalid_signature',
                        'Invalid signature.'
                    ),
                    'invalid_signature'
                );
            }
        } catch (\Exception $e) {
            $this->handleError(
                $e->getMessage(),
                'crypto_failure'
            );
        }
        return false;
    }

    /**
     * Verify pure ECDSA signature (secp256k1).
     *
     * @param $message sha256 string
     * @param $signature
     * @param $pubKey
     * @return bool
     */
    public function verifyEcdsaSignature($message, $signature, $pubKey)
    {
        $key = $this->elipticCurve->keyFromPublic($pubKey, 'hex');

        return $key->verify(hash('sha256', $message), $signature);
    }

    /**
     * Verify Ethereum signature.
     *
     * @param $message
     * @param $signature
     * @param $address
     * @return bool
     */
    public function verifyEthSignature($message, $signature, $address)
    {
        $msglen = strlen($message);

        try {
            $hash = Keccak::hash("\x19Ethereum Signed Message:\n{$msglen}{$message}", 256);
        } catch (\Exception $e) {
            $this->handleError(
                $e->getMessage(),
                'keccak_hash_failure'
            );
        }

        $sign = [
            "r" => substr($signature, 2, 64),
            "s" => substr($signature, 66, 64)
        ];
        $recid = ord(hex2bin(substr($signature, 130, 2))) - 27;
        if ($recid != ($recid & 1))
            return false;
        try {
            $pubkey = $this->elipticCurve->recoverPubKey($hash, $sign, $recid);
        } catch (\Exception $e) {
            $this->handleError(
                $e->getMessage(),
                'pub_key_failure'
            );
        }

        return strtolower($address) == strtolower($this->pubKeyToAddress($pubkey));
    }

    /**
     * Convert public key to address.
     * Eth specific.
     *
     * @param $pubkey
     * @return string
     */
    public function pubKeyToAddress($pubkey)
    {
        try {
            $address = "0x" . substr(Keccak::hash(substr(hex2bin($pubkey->encode("hex")), 1), 256), 24);
        } catch (\Exception $e) {
            $this->handleError(
                $e->getMessage(),
                'address_extraction_failure'
            );
        }

        return $address;
    }

    /**
     * Get the allowed authorization methods preceding the payload.
     *
     * @return \Illuminate\Config\Repository|mixed|string
     */
    public function getAuthorizationMethod()
    {
        return config(
            'ecdsaauth.authorization_methods',
            ['eth', 'ecdsa']
        );
    }

    /**
     * Decode the actual payload.
     *
     * @param $data
     * @return mixed
     */
    public function decodeAuthData($data)
    {
        $authData = json_decode(
            base64_decode(
                $this->cleanAuthorization($data)
            )
        );

        if (!$authData) {
            $this->handleError(
                config(
                    'ecdsaauth.error_messages.invalid_auth_data',
                    'Invalid authentication data.'
                ),
                'invalid_auth_data'
            );
        }
        return $authData;
    }

    /**
     * Cleans authorization string, removes the method name.
     *
     * @param $data
     * @return mixed
     */
    public function cleanAuthorization($data)
    {
        return trim(explode(' ', $data)[1]);
    }

    /**
     * Check if the user is registered.
     *
     * @param string $property
     * @param $object
     * @return mixed
     */
    public function checkUser($property = 'email', $object)
    {
        $userClass = config(
            'ecdsaauth.user_provider',
            \App\User::class
        );

        $user = $userClass::where($property, $object->{$property})->first();

        if (is_null($user)) {
            $this->handleError(
                config(
                    'ecdsaauth.error_messages.user_not_found',
                    'User not found.'
                ),
                'user_not_found'
            );
        }

        if (config(
            'ecdsaauth.verification',
            false
        )) {
            $this->checkUserVerified($user);
        }

        return $user;
    }

    /**
     * Check if the user is verified.
     *
     * @param $user
     * @return bool
     */
    public function checkUserVerified($user)
    {
        $verifiedField = config(
            'ecdsaauth.verified_field',
            'email_verified'
        );

        $verifiedPassCondition = config(
            'ecdsaauth.verified_pass_condition',
            1
        );

        if ($user->{$verifiedField} != $verifiedPassCondition) {
            $this->handleError(
                config(
                    'ecdsaauth.error_messages.user_not_verified',
                    'User not verified.'
                ),
                'user_not_verified'
            );
        }
        return true;
    }

    /**
     * Validate the authorization string sent in header.
     *
     * @param $data
     * @return bool|string
     */
    public function validateAuthorizationHash($data)
    {
        $pure = $this->cleanAuthorization($data);
        $hashed = hash('sha256', $pure);

        if (!$this->isUsed($hashed)) {
            return $hashed;
        }

        return $this->handleError(
            config(
                'ecdsaauth.error_messages.hash_already_used',
                'Hash already used.'
            ),
            'hash_already_used'
        );
    }

    /**
     * Check if the hashed payload has already been used.
     * If so, it is invalid and an attempt of replay attack.
     *
     * @param $hash
     * @return bool
     */
    public function isUsed($hash)
    {
        // @TODO implement the check
        return false;
    }

    /**
     * Invalidates the hash.
     *
     * @param $hash
     */
    public function invalidateHash($hash)
    {
        // @TODO implement invalidation.
        // You could save it in a file and look it up afterwards
        // in the isUsed() method.
    }

    /**
     * Logs the error message however you choose.
     *
     * @param $message
     */
    public function logError($message)
    {
        Log::debug($message);
    }

    /**
     * Handles the error event.
     * Writes message to log and throws an exception.
     *
     * @param $logMessage
     * @param $errorMessage
     */
    public function handleError($logMessage, $errorMessage)
    {
        if ($logMessage) {
            $this->logError($logMessage);
        }

        throw new UnauthorizedHttpException(
            '',
            config(
                'ecdsaauth.error_messages.' . $errorMessage,
                $errorMessage
            )
        );
    }

    /**
     * Get the name of the verification method for specific encryption type.
     *
     * @return string
     */
    public function verificationMethodName($request)
    {
        $authHeader = $request->headers->get(
            config(
                'ecdsaauth.authorization_header',
                'authorization'
            )
        );

        $allowedMethods = $this->getAuthorizationMethod();
        $requestedMethod = strtolower(trim(explode(' ', $authHeader)[0]));

        if (!in_array($requestedMethod, $allowedMethods)) {
            $this->handleError(false, 'method_not_allowed');
        }

        return 'verify' . ucfirst($requestedMethod) . 'Signature';
    }
}
