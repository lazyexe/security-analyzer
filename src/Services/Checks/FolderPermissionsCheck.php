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
                    $issues[] = "Folder {$folder} has insecure permissions ({$perms})!";
                }
            }
        }
        return $issues;
    }
}
