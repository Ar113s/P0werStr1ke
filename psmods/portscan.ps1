$IPADDRESS = Read-Host "[P3NShH3LL]  Enter the IP address to scan:"
1..65536 | % {echo ((new-object Net.Sockets.TcpClient).Connect($IPADDRESS, $_)) “Port $_ is open!”} 2>$null