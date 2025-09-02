<?php

namespace SecurityAnalyzer\Services\Checks;

class ForceHttpsCheck
{
    protected $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        $middlewareFile = $this->path . '/app/Http/Middleware/TrustProxies.php';

        if (!file_exists($middlewareFile)) {
            $issues[] = [
                'type' => 'Force HTTPS Missing',
                'severity' => 'high',
                'message' => 'TrustProxies middleware not found.',
                'file' => 'app/Http/Middleware/TrustProxies.php',
                'line' => 0,
                'recommendation' => 'Create TrustProxies middleware and enable forceScheme("https") in production.'
            ];
            return $issues;
        }

        $content = file_get_contents($middlewareFile);
        $lines = explode("\n", $content);
        $found = false;

        foreach ($lines as $lineNumber => $line) {
            if (stripos($line, "forceScheme('https')") !== false || stripos($line, 'forceScheme("https")') !== false) {
                $found = true;
                break;
            }
        }

        if (!$found) {
            $issues[] = [
                'type' => 'Force HTTPS Not Enforced',
                'severity' => 'high',
                'message' => 'forceScheme("https") is not called in TrustProxies middleware.',
                'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $middlewareFile),
                'line' => 0,
                'recommendation' => 'Add forceScheme("https") in the TrustProxies middleware to enforce HTTPS.'
            ];
        }

        return $issues;
    }
}
