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
        if ($this->app->runningInConsole()) {
            $this->commands([
                Commands\ScanSecurity::class,
            ]);
        }
    }
}
