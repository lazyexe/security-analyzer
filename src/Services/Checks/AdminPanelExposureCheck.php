<?php

namespace SecurityAnalyzer\Services\Checks;

class AdminPanelExposureCheck
{
    protected $path;
    protected $excludeDirs;

    protected $adminRoutes = ['/telescope', '/horizon', '/nova', '/admin', '/administrator'];

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
                'type' => 'Admin Panel Exposure',
                'severity' => 'high',
                'message' => 'routes/web.php not found.',
                'file' => 'routes/web.php',
                'line' => 0,
                'recommendation' => 'Ensure sensitive admin routes are protected with auth middleware.'
            ];
            return $issues;
        }

        $lines = explode("\n", file_get_contents($routesFile));

        foreach ($lines as $lineNumber => $line) {
            foreach ($this->adminRoutes as $route) {
                if (stripos($line, $route) !== false && stripos($line, 'middleware') === false) {
                    $issues[] = [
                        'type' => 'Admin Panel Exposure',
                        'severity' => 'high',
                        'message' => "Route '{$route}' is accessible without authentication.",
                        'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $routesFile),
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Add auth/verified middleware to protect this route.'
                    ];
                }
            }
        }

        return $issues;
    }
}
