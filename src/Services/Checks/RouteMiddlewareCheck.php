<?php

namespace SecurityAnalyzer\Services\Checks;

use Illuminate\Support\Str;

class RouteMiddlewareCheck
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

        $routesFile = $this->path . '/routes/web.php';
        if (!file_exists($routesFile)) {
            $issues[] = [
                'type' => 'Route Middleware Missing',
                'severity' => 'high',
                'message' => 'routes/web.php not found.',
                'file' => 'routes/web.php',
                'line' => 0,
                'recommendation' => 'Ensure routes/web.php exists and contains proper middleware protection.'
            ];
            return $issues;
        }

        $content = file_get_contents($routesFile);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            $line = trim($line);
            if (preg_match('/Route::(get|post|put|delete)\([\'"]((admin|dashboard)\/[^\'"]+)[\'"]/', $line, $matches)) {
                $hasMiddleware = stripos($line, 'middleware') !== false;
                if (!$hasMiddleware) {
                    $issues[] = [
                        'type' => 'Route Middleware Missing',
                        'severity' => 'high',
                        'message' => "Route '{$matches[2]}' does not have auth or verified middleware.",
                        'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $routesFile),
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Add auth/verified middleware to secure this route.'
                    ];
                }
            }
        }

        return $issues;
    }
}
