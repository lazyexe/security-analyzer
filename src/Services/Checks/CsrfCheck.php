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
            preg_match_all('/<form[^>]*>/i', $content, $matches);
            foreach ($matches[0] as $formTag) {
                if (stripos($formTag, '@csrf') === false) {
                    $issues[] = "Form missing CSRF token in: {$file}";
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
