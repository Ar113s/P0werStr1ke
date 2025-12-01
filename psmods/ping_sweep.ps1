$IPBase = Read-Host "Enter the base IP address (e.g., 192.168.1)"

for ($i = 1; $i -le 254; $i++) { ping -n 1 -w 100 "$IPBase.$i" | Select-String "Reply" }