<?php

namespace SecurityAnalyzer\Services\Checks;

class FolderPermissionsCheck
{
    protected $path;

    protected $folders = ['storage', 'bootstrap/cache'];

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        foreach ($this->folders as $folder) {
            $fullPath = $this->path . '/' . $folder;
            if (is_dir($fullPath)) {
                $perms = substr(sprintf('%o', fileperms($fullPath)), -4);
                if ($perms === '0777' || $perms === '0666') {
                    $issues[] = [
                        'type' => 'Insecure Permissions',
                        'severity' => 'medium',
                        'message' => 'Folder has insecure permissions',
                        'file' => $folder,
                        'line' => 1,
                        'recommendation' => "Change folder permissions from {$perms} to 0755 or more restrictive"
                    ];
                }
            }
        }
        return $issues;
    }
}
