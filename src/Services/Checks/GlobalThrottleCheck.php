<?php

namespace SecurityAnalyzer\Services\Checks;

class GlobalThrottleCheck
{
    protected $path;
    protected $excludeDirs;

    public function __construct($path, $excludeDirs = [])
    {
        $this->path = $path;
        $this->excludeDirs = $excludeDirs;
    }

    public function run()
    {
        $issues = [];
        $providerFile = $this->path . '/app/Providers/RouteServiceProvider.php';

        if (!file_exists($providerFile)) {
            $issues[] = [
                'type' => 'Global Throttle Missing',
                'severity' => 'high',
                'message' => 'RouteServiceProvider.php not found.',
                'file' => 'app/Providers/RouteServiceProvider.php',
                'line' => 0,
                'recommendation' => 'Ensure global API rate limits are defined in RouteServiceProvider.'
            ];
            return $issues;
        }

        $content = file_get_contents($providerFile);
        if (stripos($content, 'limit') === false) {
            $issues[] = [
                'type' => 'Global Throttle Missing',
                'severity' => 'medium',
                'message' => 'No default rate limiting found in RouteServiceProvider.',
                'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $providerFile),
                'line' => 0,
                'recommendation' => 'Define default rate limiting for API routes.'
            ];
        }

        return $issues;
    }
}
