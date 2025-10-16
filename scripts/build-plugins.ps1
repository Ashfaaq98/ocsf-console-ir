# PowerShell script to build Console-IR plugins

param(
    [string]$Plugin = "all",
    [switch]$Help
)

if ($Help) {
    Write-Host "Console-IR Plugin Builder"
    Write-Host ""
    Write-Host "Usage: .\build-plugins.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Plugin <name>    Build specific plugin (geoip, llm, misp, or all)"
    Write-Host "  -Help             Show this help message"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\build-plugins.ps1                 # Build all plugins"
    Write-Host "  .\build-plugins.ps1 -Plugin llm     # Build only LLM plugin"
    Write-Host "  .\build-plugins.ps1 -Plugin geoip   # Build only GeoIP plugin"
    Write-Host "  .\build-plugins.ps1 -Plugin misp    # Build only MISP plugin"
    exit 0
}

$BuildDir = "bin"
$PluginsDir = "plugins"

# Ensure build directory exists
if (!(Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

function Build-Plugin {
    param([string]$PluginName)
    
    $PluginPath = Join-Path $PluginsDir $PluginName
    if (!(Test-Path $PluginPath)) {
        Write-Host "Plugin '$PluginName' not found in $PluginsDir" -ForegroundColor Red
        return $false
    }
    
    if (!(Test-Path (Join-Path $PluginPath "main.go"))) {
        Write-Host "No main.go found in plugin '$PluginName'" -ForegroundColor Yellow
        return $false
    }
    
    Write-Host "Building plugin: $PluginName" -ForegroundColor Green
    
    Push-Location $PluginPath
    try {
        # Initialize go modules if needed
        if (!(Test-Path "go.mod")) {
            Write-Host "  Initializing Go modules..." -ForegroundColor Yellow
            go mod init "github.com/Ashfaaq98/ocsf-console-ir/plugins/$PluginName"
            go mod tidy
        }
        
        # Build the plugin
        $OutputPath = "../../$BuildDir/$PluginName"
        $result = go build -o $OutputPath . 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  ✓ Plugin '$PluginName' built successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  ✗ Failed to build plugin '$PluginName':" -ForegroundColor Red
            Write-Host "    $result" -ForegroundColor Red
            return $false
        }
    }
    finally {
        Pop-Location
    }
}

# Main execution
Write-Host "Console-IR Plugin Builder" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

$success = 0
$total = 0

if ($Plugin -eq "all") {
    # Build all plugins
    $plugins = Get-ChildItem -Path $PluginsDir -Directory | Where-Object { 
        Test-Path (Join-Path $_.FullName "main.go") 
    }
    
    foreach ($pluginDir in $plugins) {
        $total++
        if (Build-Plugin $pluginDir.Name) {
            $success++
        }
    }
} else {
    # Build specific plugin
    $total = 1
    if (Build-Plugin $Plugin) {
        $success = 1
    }
}

Write-Host ""
Write-Host "Build Summary:" -ForegroundColor Cyan
Write-Host "  Successful: $success/$total" -ForegroundColor Green

if ($success -gt 0) {
    Write-Host ""
    Write-Host "Plugin Usage Examples:" -ForegroundColor Cyan
    
    if ((Test-Path (Join-Path $BuildDir "geoip")) -or ($Plugin -eq "geoip")) {
        Write-Host ""
        Write-Host "GeoIP Plugin:" -ForegroundColor Yellow
        Write-Host "  .\bin\geoip --redis redis://localhost:6379"
    }
    
    if ((Test-Path (Join-Path $BuildDir "llm")) -or ($Plugin -eq "llm")) {
        Write-Host ""
        Write-Host "LLM Plugin:" -ForegroundColor Yellow
        Write-Host "  # OpenAI:"
        Write-Host "  .\bin\llm --api-key YOUR_OPENAI_KEY --provider openai --model gpt-3.5-turbo"
        Write-Host ""
        Write-Host "  # Claude:"
        Write-Host "  .\bin\llm --api-key YOUR_CLAUDE_KEY --provider claude --model claude-3-sonnet-20240229"
        Write-Host ""
        Write-Host "  # Environment variable:"
        Write-Host "  `$env:LLM_API_KEY = 'your-key-here'"
        Write-Host "  .\bin\llm --provider openai"
    }

    if ((Test-Path (Join-Path $BuildDir "misp")) -or ($Plugin -eq "misp")) {
        Write-Host ""
        Write-Host "MISP Plugin:" -ForegroundColor Yellow
        Write-Host "  Production:"
        Write-Host "    .\bin\misp --misp-url https://misp.company.com --api-key YOUR_KEY"
        Write-Host "  Development:"
        Write-Host "    .\bin\misp --misp-url http://localhost:8080 --api-key dev-key"
        Write-Host "  Dry Run:"
        Write-Host "    .\bin\misp --dry-run"
        Write-Host ""
        Write-Host "  Environment variables:"
        Write-Host "    `$env:MISP_URL = 'https://misp.example.com'"
        Write-Host "    `$env:MISP_API_KEY = 'your-api-key-here'"
    }
}

if ($success -lt $total) {
    exit 1
}
