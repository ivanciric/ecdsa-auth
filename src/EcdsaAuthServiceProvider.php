<?php
namespace ivanciric\EcdsaAuth;

use Illuminate\Support\ServiceProvider;

class EcdsaAuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/config/ecdsaauth.php' => config_path('ecdsaauth.php'),
        ]);

        // @TODO setup translations
        // $this->loadTranslationsFrom(
        //    __DIR__.'/translations', 'ecdsa-auth'
        // );
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(EcdsaAuth::class, function () {
            return new EcdsaAuth();
        });

        $this->app->alias(EcdsaAuth::class, 'ecdsa-auth');
    }
}