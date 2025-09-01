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
                $issues[] = "Sensitive file found: {$file}";
            }
        }
        return $issues;
    }
}
