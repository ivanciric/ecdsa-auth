<?php
namespace ivanciric\EcdsaAuth;

use Illuminate\Support\ServiceProvider as LaravelServiceProvider;

class ServiceProvider extends LaravelServiceProvider
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
        $this->app->singleton(Authenticator::class, function () {
            return new Authenticator();
        });

        $this->app->alias(Authenticator::class, 'ecdsa-auth');
    }
}