<?php

namespace Anomander\Sanitizr;

use Anomander\Sanitizr\Services\Sanitizer;
use Illuminate\Support\ServiceProvider;

class SanitizrServiceProvider extends ServiceProvider
{
    public function boot()
    {
        // Publish config file
        $this->publishes([
            __DIR__ . '/../config/sanitizr.php' => config_path('sanitizr.php'),
        ], 'config');

        // Publish middleware
        $this->publishes([
            __DIR__ . '/../src/Http/Middleware/AutoSan.php' => app_path('Http/Middleware/AutoSan.php'),
        ], 'middleware');
    }

    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sanitizr.php', 'sanitizr');

        $this->app->singleton(Sanitizer::class, function ($app) {
            return new Sanitizer(config('sanitizr.filters'));
        });
    }
}