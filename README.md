# 🔒 Laravel Security Analyzer

**Scan your Laravel project for security vulnerabilities in seconds!**

Detects common security issues including:

* 🗝️ Exposed `.env` files
* 🐞 Debug mode enabled / Missing APP\_KEY
* 📂 Sensitive files exposed
* 🔐 Unsafe folder permissions
* 📦 Outdated packages with vulnerabilities
* 💉 Potential SQL Injection & XSS
* 🛡️ Missing CSRF protection
* 🌐 Force HTTPS not enforced
* 🚫 Insecure CORS policy
* 🛠️ Route Middleware missing (admin/dashboard routes)
* ⏱️ API Rate Limiting missing
* ⚡ Global Throttle configuration missing
* 🔑 Weak Password Hash Driver
* 🏛️ Admin Panel exposure (`/telescope`, `/horizon`, `/administrator`, `/admin`)
* 📁 Storage symlink invalid or misconfigured
* 🔍 Directory index exposed
* 💾 Backup files found in project root or public folder

---

## ⚡ Quick Installation

**Option 1: Auto Installer (Recommended)**

1. Copy the `security-analyzer` folder to your Laravel project root
2. Run the installer:

```bash
php security-analyzer/install.php
```

**That's it!** The installer will automatically:
- Create the packages directory
- Copy files to the right location
- Update your composer.json
- Registering SecurityAnalyzer
- Run composer dump-autoload
- Publish configuration files

**Option 2: Manual Installation**

If you prefer manual setup:

1. Create `packages` folder in your Laravel project root
2. Copy `security-analyzer` folder into `packages/`
3. Add to your `composer.json`:

```json
"autoload": {
    "psr-4": {
        "SecurityAnalyzer\\": "packages/security-analyzer/src/"
    }
}
```

4. Run:

```bash
composer dump-autoload
php artisan vendor:publish --provider="SecurityAnalyzer\SecurityAnalyzerServiceProvider" --tag=config
```

---

## 🚀 Usage

**Basic scan:**
```bash
php artisan security:scan
```

**Advanced options:**
```bash
# Scan specific path
php artisan security:scan --path=/path/to/scan

# Generate HTML report
php artisan security:scan --output=html

# Generate all report formats
php artisan security:scan --output=all

# Skip saving report files
php artisan security:scan --no-report
```

---

## ⚙️ Configuration

Edit `config/security-analyzer.php` to customize:

```php
return [
    'report_path' => storage_path('security-report.json'),
    'report_html' => storage_path('security-report.html'),

    'checks' => [
        'env_file'           => true,
        'debug_and_key'      => true,
        'sensitive_files'    => true,
        'folder_permissions' => true,
        'outdated_packages'  => false, // Disabled by default
        'php_code_risks'     => true,
        'csrf_check'         => true,
		'force_https'         => true,
		'cors_check'          => true,
		'route_middleware'    => true,
		'api_rate_limit'      => true,
		'global_throttle'     => true,
		'password_hash'       => true,
		'admin_panel'         => true,
		'storage_symlink'     => true,
		'directory_index'     => true,
		'backup_file'         => true,
    ],

    'exclude_dirs' => [
        'bootstrap', 'node_modules', 'packages', 'tests', 'vendor',
    ],

    'exclude_files' => [
        '*.log', '*.tmp',
    ],
];
```

---

## 📊 Sample Output

```
🔒 Laravel Security Analyzer
================================
📁 Scanning path: /path/to/your/project

🔍 Running security checks...
████████████████████████████████████████ 100%

⚠️  Found 3 security issue(s):

🚨 Environment Issues (2 issue(s))
   • .env file is publicly accessible
     📄 File: .env
     💡 Fix: Move .env file outside public directory

   • Debug mode is enabled in production
     📄 File: .env
     💡 Fix: Set APP_DEBUG=false in production

🚨 File Permissions (1 issue(s))
   • Storage directory has unsafe permissions
     📄 File: storage/
     💡 Fix: Set permissions to 755

💾 Saving reports...
📄 Backup JSON report saved: /storage/security-report.json
```

---

## 🎯 Features

- **🚀 Zero Configuration**: Works out of the box with sensible defaults
- **📱 Multiple Output Formats**: Console, JSON, and HTML reports
- **🎨 Beautiful Reports**: Color-coded console output and styled HTML reports
- **⚡ Fast Scanning**: Optimized for large Laravel projects
- **🔧 Customizable**: Easily configure which checks to run
- **📦 Laravel Integration**: Native Artisan command support
- **🔄 Auto-Discovery**: Automatically registers with Laravel

---

## 🛠️ Requirements

- PHP >= 8.2
- Laravel >= 12.0

---

## 📝 License

This package is open-sourced software licensed under the [MIT license](LICENSE).

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📞 Support

If you encounter any issues or have questions, please open an issue on the repository.

**Happy securing! 🔒**