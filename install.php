<?php

/**
 * Security Analyzer Package Installer
 * Automatically sets up the package in Laravel project
 */

class SecurityAnalyzerInstaller
{
    private $projectRoot;
    private $packagePath;

    public function __construct()
    {
        $this->projectRoot = getcwd();
        $this->packagePath = __DIR__;
    }

    public function install()
    {
        echo "🔒 Installing Security Analyzer Package...\n\n";

        // Step 1: Check if we're in Laravel project
        if (!$this->isLaravelProject()) {
            echo "❌ Error: This is not a Laravel project root directory.\n";
            echo "Please run this installer from your Laravel project root.\n";
            return false;
        }

        // Step 2: Create packages directory
        $this->createPackagesDirectory();

        // Step 3: Copy package to packages directory
        $this->copyPackage();

        // Step 4: Update composer.json
        $this->updateComposerJson();

        // Step 5: Run composer dump-autoload
        $this->runComposerDumpAutoload();

        // Step 6: Register Service Provider
        $this->registerServiceProvider();

        // Step 7: Publish config
        $this->publishConfig();

        echo "\n✅ Security Analyzer installed successfully!\n";
        echo "\n📖 Usage:\n";
        echo "   php artisan security:scan\n";
        echo "\n📁 Config file: config/security-analyzer.php\n";
        echo "📊 Reports will be saved to storage/ directory\n\n";

        return true;
    }

    private function isLaravelProject()
    {
        return file_exists($this->projectRoot . '/artisan') && 
               file_exists($this->projectRoot . '/composer.json');
    }

    private function createPackagesDirectory()
    {
        $packagesDir = $this->projectRoot . '/packages';
        if (!is_dir($packagesDir)) {
            mkdir($packagesDir, 0755, true);
            echo "📁 Created packages directory\n";
        }
    }

    private function copyPackage()
    {
        $targetDir = $this->projectRoot . '/packages/security-analyzer';
        
        if (is_dir($targetDir)) {
            echo "📦 Package directory already exists, updating...\n";
            $this->deleteDirectory($targetDir);
        }

        $this->copyDirectory($this->packagePath, $targetDir);
        echo "📦 Package copied to packages/security-analyzer\n";
    }

    private function updateComposerJson()
    {
        $composerFile = $this->projectRoot . '/composer.json';
        $composer = json_decode(file_get_contents($composerFile), true);

        // Add PSR-4 autoloading
        if (!isset($composer['autoload']['psr-4']['SecurityAnalyzer\\'])) {
            $composer['autoload']['psr-4']['SecurityAnalyzer\\'] = 'packages/security-analyzer/src/';
            file_put_contents($composerFile, json_encode($composer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            echo "📝 Updated composer.json with PSR-4 autoloading\n";
        } else {
            echo "📝 PSR-4 autoloading already configured\n";
        }
    }

    private function runComposerDumpAutoload()
    {
        echo "🔄 Running composer dump-autoload...\n";
        exec('composer dump-autoload', $output, $returnCode);
        
        if ($returnCode === 0) {
            echo "✅ Composer autoload updated\n";
        } else {
            echo "⚠️  Please run 'composer dump-autoload' manually\n";
        }
    }

    private function registerServiceProvider()
	{
		$providerClass = 'SecurityAnalyzer\\SecurityAnalyzerServiceProvider::class';

		$configFile = $this->projectRoot . '/config/app.php';
		if (file_exists($configFile)) {
			$config = file_get_contents($configFile);

			if (strpos($config, $providerClass) !== false) {
				echo "📝 Service Provider already registered in config/app.php\n";
				return;
			}

			$pattern = "/(\s*'providers'\s*=>\s*\[.*?)(\s*\],)/s";

			if (preg_match($pattern, $config, $matches)) {
				$replacement = $matches[1] . "\n\n        // Security Analyzer\n        " . $providerClass . "," . $matches[2];
				$config = preg_replace($pattern, $replacement, $config);

				file_put_contents($configFile, $config);
				echo "📝 Service Provider registered in config/app.php\n";
				return;
			} else {
				echo "⚠️ Could not auto-register in config/app.php, trying AppServiceProvider.php...\n";
			}
		} else {
			echo "⚠️ config/app.php not found, trying AppServiceProvider.php...\n";
		}

		$providerFile = $this->projectRoot . '/app/Providers/AppServiceProvider.php';
		if (!file_exists($providerFile)) {
			echo "❌ AppServiceProvider.php not found\n";
			return;
		}

		$content = file_get_contents($providerFile);

		$useStatement = "use SecurityAnalyzer\\SecurityAnalyzerServiceProvider;";
		if (strpos($content, $useStatement) === false) {
			$content = preg_replace(
				'/(use Illuminate\\\\Support\\\\ServiceProvider;)/',
				"$1\n$useStatement",
				$content,
				1
			);
			echo "📝 Added use SecurityAnalyzer\\SecurityAnalyzerServiceProvider;\n";
		} else {
			echo "✅ Use statement already exists, skipped\n";
		}

		$registerLine = '$this->app->register(SecurityAnalyzerServiceProvider::class);';
		if (strpos($content, $registerLine) === false) {
			$content = preg_replace(
				'/public function register\(\): void\s*\{\s*/',
				"public function register(): void\n    {\n        // Register SecurityAnalyzer\n        $registerLine\n        ",
				$content,
				1
			);
			echo "📝 Registered SecurityAnalyzerServiceProvider in AppServiceProvider\n";
		} else {
			echo "✅ Service Provider already registered in AppServiceProvider, skipped\n";
		}

		file_put_contents($providerFile, $content);
	}

    private function publishConfig()
    {
        echo "📋 Publishing configuration...\n";
        exec('php artisan vendor:publish --provider="SecurityAnalyzer\\SecurityAnalyzerServiceProvider" --tag=config --force', $output, $returnCode);
        
        if ($returnCode === 0) {
            echo "✅ Configuration published\n";
        } else {
            echo "⚠️  Please run 'php artisan vendor:publish --provider=\"SecurityAnalyzer\\SecurityAnalyzerServiceProvider\" --tag=config' manually\n";
        }
    }

    private function copyDirectory($src, $dst)
    {
        $dir = opendir($src);
        @mkdir($dst, 0755, true);
        
        while (($file = readdir($dir)) !== false) {
            if ($file != '.' && $file != '..') {
                if (is_dir($src . '/' . $file)) {
                    $this->copyDirectory($src . '/' . $file, $dst . '/' . $file);
                } else {
                    copy($src . '/' . $file, $dst . '/' . $file);
                }
            }
        }
        
        closedir($dir);
    }

    private function deleteDirectory($dir)
    {
        if (!is_dir($dir)) return;
        
        $files = array_diff(scandir($dir), ['.', '..']);
        
        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->deleteDirectory($path) : unlink($path);
        }
        
        rmdir($dir);
    }
}

// Run installer
if (php_sapi_name() === 'cli') {
    $installer = new SecurityAnalyzerInstaller();
    $installer->install();
} else {
    echo "This installer must be run from command line.\n";
}