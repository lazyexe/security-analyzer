<?php

namespace SecurityAnalyzer\Services\Checks;

class CsrfCheck
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
        $bladeFiles = $this->scanBladeFiles($this->path);

        foreach ($bladeFiles as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);
            
            foreach ($lines as $lineNumber => $line) {
                if (preg_match('/<form[^>]*>/i', $line)) {
                    if (stripos($line, '@csrf') === false) {
                        $issues[] = [
                            'type' => 'CSRF Protection Missing',
                            'severity' => 'high',
                            'message' => 'Form missing CSRF token protection',
                            'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $file),
                            'line' => $lineNumber + 1,
                            'recommendation' => 'Add @csrf directive inside the form tag'
                        ];
                    }
                }
            }
        }

        return $issues;
    }

    protected function scanBladeFiles($dir)
    {
        $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir));
        $files = [];
        foreach ($rii as $file) {
            if ($file->isDir()) continue;

            $pathName = $file->getPathname();

            foreach ($this->excludeDirs as $exDir) {
                if (strpos($pathName, DIRECTORY_SEPARATOR . $exDir . DIRECTORY_SEPARATOR) !== false) {
                    continue 2;
                }
            }

            if ($file->getExtension() === 'blade.php') {
                $files[] = $pathName;
            }
        }
        return $files;
    }
}
