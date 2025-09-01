<?php

namespace SecurityAnalyzer;

use Illuminate\Support\ServiceProvider;

class SecurityAnalyzerServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/security-analyzer.php', 'security-analyzer');
    }

    public function boot()
    {
        // Publish config file
        $this->publishes([
            __DIR__ . '/../config/security-analyzer.php' => config_path('security-analyzer.php'),
        ], 'config');

        // Register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                Commands\ScanSecurity::class,
            ]);
        }

        // Auto-publish config on first install if not exists
        if (!file_exists(config_path('security-analyzer.php'))) {
            $this->publishes([
                __DIR__ . '/../config/security-analyzer.php' => config_path('security-analyzer.php'),
            ], 'config');
        }
    }
}
