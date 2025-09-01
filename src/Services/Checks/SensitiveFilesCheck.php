<?php

namespace SecurityAnalyzer\Services\Checks;

class SensitiveFilesCheck
{
    protected $path;

    protected $files = [
        '.env',
        '.env.backup',
        'composer.lock',
        'storage/logs/laravel.log'
    ];

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        foreach ($this->files as $file) {
            if (file_exists($this->path . '/' . $file)) {
                $issues[] = [
                    'type' => 'Sensitive File Exposure',
                    'severity' => 'high',
                    'message' => 'Sensitive file found in public directory',
                    'file' => $file,
                    'line' => 1,
                    'recommendation' => 'Move sensitive files outside public directory or add proper access restrictions'
                ];
            }
        }
        return $issues;
    }
}
