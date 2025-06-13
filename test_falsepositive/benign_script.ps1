# Kịch bản PowerShell lành tính để kiểm tra dương tính giả
# Tạo một tệp tạm thời, ghi nội dung vào đó, đọc lại và sau đó xóa nó.

$tempFile = [System.IO.Path]::GetTempFileName()
$content = "Đây là một bài kiểm tra ghi tệp đơn giản. Timestamp: $(Get-Date)"

Write-Host "Tạo và ghi vào tệp: $tempFile"
Set-Content -Path $tempFile -Value $content

Start-Sleep -Seconds 1

Write-Host "Đọc nội dung từ tệp..."
Get-Content -Path $tempFile

Start-Sleep -Seconds 1

Write-Host "Xóa tệp..."
Remove-Item -Path $tempFile -Force

Write-Host "Kịch bản lành tính đã hoàn thành."
