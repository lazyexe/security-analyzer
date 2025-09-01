# Laravel Security Analyzer

**Laravel Security Analyzer** is a package to scan your **Laravel project workspace** and detect potential security issues, including:

* Exposed `.env` file
* Debug mode enabled / APP\_KEY not set
* Sensitive files (`composer.lock`, logs, backups)
* Folders with unsafe permissions
* Outdated composer packages
* Potential **SQL Injection** & **XSS**
* Forms **without CSRF tokens**

---

## Installation

1. Create a `packages` folder in your Laravel project root.
2. Copy the entire `security-analyzer` folder into `packages/`.
3. Add **PSR-4 autoloading** in `composer.json`:

```json
"autoload": {
    "psr-4": {
        "App\\": "app/",
        "SecurityAnalyzer\\": "packages/security-analyzer/src/"
    }
}
```

4. Run:

```bash
composer dump-autoload
```

---

## Register the Service Provider

Edit `app/Providers/AppServiceProvider.php`:

```php
<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use SecurityAnalyzer\SecurityAnalyzerServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if (class_exists(SecurityAnalyzerServiceProvider::class)) {
            $this->app->register(SecurityAnalyzerServiceProvider::class);
        }
    }

    public function boot(): void
    {
        //
    }
}
```

---

## Configuration

Configuration file: `packages/security-analyzer/src/config/security-analyzer.php`

```php
<?php

return [
    'report_path' => storage_path('security-report.json'),
    'report_html' => storage_path('security-report.html'),

    'checks' => [
        'env_file'           => true,
        'debug_and_key'      => true,
        'sensitive_files'    => true,
        'folder_permissions' => true,
        'outdated_packages'  => true,
        'php_code_risks'     => true,
        'csrf_check'         => true,
    ],

    'exclude_dirs' => [
        'bootstrap',
        'node_modules',
        'packages',
        'tests',
        'vendor',
    ],

    'exclude_files' => [
        '*.log',
        '*.tmp',
    ],
];
```

---

## Usage

Run the artisan command:

```bash
php artisan security:scan --path=./
```

> Output:
> *JSON:* `storage/security-report.json`
> *HTML:* `storage/security-report.html`

---

## Packages Folder Structure

```
packages/security-analyzer/
├── src/
│   ├── Commands/
│   │   └── ScanSecurity.php             # Artisan command to run the scan
│   ├── Services/
│   │   ├── SecurityScanner.php          # Main scanner orchestrator
│   │   └── Checks/
│   │       ├── EnvFileCheck.php
│   │       ├── DebugAndKeyCheck.php
│   │       ├── SensitiveFilesCheck.php
│   │       ├── FolderPermissionsCheck.php
│   │       ├── OutdatedPackagesCheck.php
│   │       └── PhpCodeRiskCheck.php
│   ├── config/
│   │   └── security-analyzer.php        # Configuration file
│   └── SecurityAnalyzerServiceProvider.php
├── composer.json                        # Optional, if using as standalone package
└── README.md                            # Usage instructions

```