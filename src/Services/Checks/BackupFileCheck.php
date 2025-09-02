<?php

namespace SecurityAnalyzer\Services\Checks;

class BackupFileCheck
{
    protected $path;
    protected $excludeDirs;
    protected $extensions = ['sql', 'zip', 'tar', 'bak'];

    public function __construct($path, $excludeDirs = [])
    {
        $this->path = $path;
        $this->excludeDirs = $excludeDirs;
    }

    public function run()
    {
        $issues = [];
        $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->path));

        foreach ($rii as $file) {
            if ($file->isDir()) continue;
            $pathName = $file->getPathname();

            foreach ($this->excludeDirs as $exDir) {
                if (strpos($pathName, DIRECTORY_SEPARATOR . $exDir . DIRECTORY_SEPARATOR) !== false) {
                    continue 2;
                }
            }

            if (in_array($file->getExtension(), $this->extensions)) {
                $issues[] = [
                    'type' => 'Backup File Exposed',
                    'severity' => 'high',
                    'message' => "Backup file {$file->getFilename()} found in project root/public.",
                    'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $pathName),
                    'line' => 0,
                    'recommendation' => 'Move or remove backup files from publicly accessible directories.'
                ];
            }
        }

        return $issues;
    }
}
