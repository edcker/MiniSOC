$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://localhost:8000/")
$listener.Start()

Write-Host "Serving on http://localhost:8000"
Write-Host "Press Ctrl+C to stop"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $requestPath = $context.Request.Url.LocalPath.TrimStart("/")
    if ($requestPath -eq "") { $requestPath = "index.html" }

    $filePath = Join-Path (Get-Location) $requestPath

    if (!(Test-Path $filePath)) {
        $context.Response.StatusCode = 404
        $context.Response.Close()
        continue
    }

    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    $context.Response.ContentLength64 = $bytes.Length
    $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $context.Response.Close()
}
