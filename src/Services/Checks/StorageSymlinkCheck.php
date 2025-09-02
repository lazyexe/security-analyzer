<?php

namespace SecurityAnalyzer\Services\Checks;

class StorageSymlinkCheck
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
        $link = $this->path . '/public/storage';
        $target = $this->path . '/storage/app/public';

        if (!is_link($link) || readlink($link) !== $target) {
            $issues[] = [
                'type' => 'Storage Symlink Invalid',
                'severity' => 'high',
                'message' => 'Public storage symlink is missing or incorrect.',
                'file' => 'public/storage',
                'line' => 0,
                'recommendation' => 'Run "php artisan storage:link" to create correct symlink.'
            ];
        }

        return $issues;
    }
}
