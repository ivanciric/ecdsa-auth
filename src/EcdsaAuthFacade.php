<?php
namespace ivanciric\EcdsaAuth;

use Illuminate\Support\Facades\Facade;

class EcdsaAuthFacade extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'ecdsa-auth';
    }
}