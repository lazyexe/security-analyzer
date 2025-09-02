<?php

namespace SecurityAnalyzer\Services\Checks;

class ApiRateLimitingCheck
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
        $routesFile = $this->path . '/routes/api.php';

        if (!file_exists($routesFile)) {
            $issues[] = [
                'type' => 'API Rate Limiting Missing',
                'severity' => 'high',
                'message' => 'routes/api.php not found.',
                'file' => 'routes/api.php',
                'line' => 0,
                'recommendation' => 'Ensure routes/api.php exists and API routes have throttle middleware.'
            ];
            return $issues;
        }

        $lines = explode("\n", file_get_contents($routesFile));

        foreach ($lines as $lineNumber => $line) {
            $line = trim($line);
            if (preg_match('/Route::(get|post|put|delete)\(/', $line) && stripos($line, 'throttle') === false) {
                $issues[] = [
                    'type' => 'API Rate Limiting Missing',
                    'severity' => 'high',
                    'message' => 'API route missing throttle middleware.',
                    'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $routesFile),
                    'line' => $lineNumber + 1,
                    'recommendation' => 'Add throttle middleware to limit API request rate.'
                ];
            }
        }

        return $issues;
    }
}
