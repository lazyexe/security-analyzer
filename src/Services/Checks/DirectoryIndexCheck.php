<?php

namespace SecurityAnalyzer\Services\Checks;

class DirectoryIndexCheck
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
        $publicPath = $this->path . '/public';

        if (!file_exists($publicPath . '/.htaccess')) {
            $issues[] = [
                'type' => 'Directory Index Exposed',
                'severity' => 'medium',
                'message' => 'Public directory might allow directory listing.',
                'file' => 'public/.htaccess',
                'line' => 0,
                'recommendation' => 'Add .htaccess to disable directory listing or configure web server properly.'
            ];
        }

        return $issues;
    }
}
