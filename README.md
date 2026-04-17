python3 proto_scan.py 114.114.114.114 "12920-12924,80,443" --sni auto --timeout 3 --workers 64
python3 proto_scan.py 114.114.114.114 "80-90,443,8080" --out scan_results
