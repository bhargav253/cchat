# Dedicated Linode staging deployment

This deployment is intentionally **locked**. It serves the unpaired-device page
but does not enable pairing, remote Codex access, or encrypted routing until
those paths are complete and reviewed.

## 1. DNS

Create an `A` record:

```text
Type: A
Name: @
Value: <Linode public IPv4 address>
TTL: 300
```

Create an `AAAA` record only if IPv6 is configured and allowed through both
firewalls. Wait until `dig +short mycchat.win` returns the intended address.

## 2. Firewall

Apply a Linode Cloud Firewall before deploying:

- Allow inbound TCP 80 from all IPv4/IPv6 sources for ACME redirects.
- Allow inbound TCP 443 from all IPv4/IPv6 sources.
- Allow inbound TCP 22 only from the administrator's trusted IP range.
- Deny all other inbound traffic.

Mirror the policy with the host firewall. Port 8787 must never be public.

## 3. Base software

Install Git, Node.js 24, and the official Caddy package. Verify binaries before
continuing:

```bash
node --version
npm --version
caddy version
git --version
```

Node must report version 24 or newer. Do not install a separate Ubuntu `npm`
package when the selected Node distribution already includes npm.

## 4. Service account and checkout

Run as root on the Linode:

```bash
adduser --system --group --home /var/lib/cchat cchat
install -d -o cchat -g cchat -m 0700 /var/lib/cchat
install -d -o root -g cchat -m 0750 /etc/cchat
git clone https://github.com/bhargav253/cchat.git /opt/cchat
cd /opt/cchat
npm ci
npm run check
npm prune --omit=dev
chown -R root:root /opt/cchat
```

The application checkout is root-owned so the network service cannot replace
its own executable code.

## 5. Relay configuration and database

```bash
install -o root -g cchat -m 0640 /opt/cchat/deploy/relay.env.example /etc/cchat/relay.env
cd /opt/cchat
sudo -u cchat CCHAT_RELAY_DB=/var/lib/cchat/relay.sqlite npm run relay:init
```

Store the printed bootstrap token in a password manager. Do not put it in shell
history, Git, the environment file, screenshots, or chat. It will later be
consumed once by the bridge enrollment flow.

## 6. Install services

```bash
install -o root -g root -m 0644 /opt/cchat/deploy/cchat-relay.service /etc/systemd/system/cchat-relay.service
install -o root -g root -m 0644 /opt/cchat/deploy/Caddyfile /etc/caddy/Caddyfile
systemctl daemon-reload
systemctl enable --now cchat-relay.service
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

## 7. Verify the locked deployment

```bash
systemctl status cchat-relay.service --no-pager
journalctl -u cchat-relay.service -n 50 --no-pager
curl -fsS http://127.0.0.1:8787/healthz
curl -fsSI https://mycchat.win/
```

The public page must say that the device is not paired. At this stage there is
no route capable of reaching Codex.

## Updates

Do not run `git pull` as the service account. As root:

```bash
cd /opt/cchat
git fetch --prune origin
git checkout --detach <reviewed-commit-sha>
npm ci
npm run check
npm prune --omit=dev
systemctl restart cchat-relay.service
```

Pin reviewed commit hashes rather than deploying a moving branch implicitly.
