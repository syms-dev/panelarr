# Panelarr on Saltbox

This guide puts Panelarr on a [Saltbox](https://github.com/saltyorg/Saltbox) server behind Saltbox's own Traefik, with Authelia handling sign-in. It was checked on a real Saltbox server (Traefik 3, Authelia, Cloudflare DNS) from a fresh install through setup.

Panelarr isn't a Saltbox app, so `sb install` doesn't know about it and `sb update` leaves it alone. It runs as a plain Docker Compose project next to the Saltbox containers.

## Running alongside saltbox-ui

[saltbox-ui](https://github.com/syms-dev/saltbox-ui) runs on the host as a systemd service and manages the server itself. Panelarr runs in a container and handles the media stack: queues, downloads, the calendar and container controls. They don't share ports, files or config. Give each its own subdomain (for example `saltbox.example.com` and `panelarr.example.com`) and run both.

## 1. Find your Saltbox settings

Panelarr's labels should match the ones Saltbox gives its own apps. Read them off any Saltbox app, such as Sonarr:

```bash
docker inspect sonarr --format '{{json .Config.Labels}}' | tr ',' '\n' | grep -E 'routers.sonarr\.(middlewares|tls)'
```

You need three things from that output:

- **Certificate resolver**: `cfdns` when Saltbox uses Cloudflare DNS, otherwise usually `letsencrypt`.
- **Middlewares**: typically `globalHeaders@file,secureHeaders@file,robotHeaders@file,cloudflarewarp@docker,authelia@docker`. `cloudflarewarp@docker` only exists when your domain is on Cloudflare.
- **TLS domains and options**: your domain and the `securetls@file` options.

## 2. Create the compose file

```bash
sudo mkdir -p /opt/panelarr/config
sudo chown -R "$(id -u):$(id -g)" /opt/panelarr
```

Save this as `/opt/panelarr/docker-compose.yml`. Replace `example.com` with your domain, and adjust the resolver and middlewares to match step 1.

```yaml
services:
  panelarr:
    image: ghcr.io/syms-dev/panelarr:latest
    container_name: panelarr
    hostname: panelarr
    restart: unless-stopped
    environment:
      - TZ=America/Toronto
      # Lets the setup wizard run through the domain (it is otherwise limited to
      # an IP address or localhost), and makes Panelarr refuse every other hostname.
      - PANELARR_ALLOWED_HOSTS=panelarr.example.com
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /opt/panelarr/config:/config
    networks:
      - saltbox
    # No "ports:" entry. Traefik reaches Panelarr over the saltbox network;
    # a published port would let anyone skip Authelia.
    labels:
      - autoheal=true
      - traefik.enable=true
      # http -> https
      - traefik.http.routers.panelarr-http.entrypoints=web
      - traefik.http.routers.panelarr-http.rule=Host(`panelarr.example.com`)
      - traefik.http.routers.panelarr-http.middlewares=globalHeaders@file,redirect-to-https@docker,robotHeaders@file,cloudflarewarp@docker,authelia@docker
      - traefik.http.routers.panelarr-http.priority=20
      - traefik.http.routers.panelarr-http.service=panelarr
      # the app, behind Authelia
      - traefik.http.routers.panelarr.entrypoints=websecure
      - traefik.http.routers.panelarr.rule=Host(`panelarr.example.com`)
      - traefik.http.routers.panelarr.middlewares=globalHeaders@file,secureHeaders@file,robotHeaders@file,cloudflarewarp@docker,authelia@docker
      - traefik.http.routers.panelarr.priority=20
      - traefik.http.routers.panelarr.service=panelarr
      - traefik.http.routers.panelarr.tls.certresolver=cfdns
      - traefik.http.routers.panelarr.tls.domains[0].main=example.com
      - traefik.http.routers.panelarr.tls.domains[0].sans=*.example.com
      - traefik.http.routers.panelarr.tls.options=securetls@file
      # the calendar feed skips Authelia (calendar apps can't sign in) and is
      # protected by its own token instead
      - traefik.http.routers.panelarr-feed.entrypoints=websecure
      - traefik.http.routers.panelarr-feed.rule=Host(`panelarr.example.com`) && Path(`/api/calendar/feed.ics`)
      - traefik.http.routers.panelarr-feed.middlewares=globalHeaders@file,secureHeaders@file,robotHeaders@file,cloudflarewarp@docker
      - traefik.http.routers.panelarr-feed.priority=30
      - traefik.http.routers.panelarr-feed.service=panelarr
      - traefik.http.routers.panelarr-feed.tls.certresolver=cfdns
      - traefik.http.routers.panelarr-feed.tls.domains[0].main=example.com
      - traefik.http.routers.panelarr-feed.tls.domains[0].sans=*.example.com
      - traefik.http.routers.panelarr-feed.tls.options=securetls@file
      - traefik.http.services.panelarr.loadbalancer.server.port=8000

networks:
  saltbox:
    external: true
```

On **0.4.0-alpha**, set `PANELARR_ALLOWED_HOSTS=panelarr.example.com,localhost`. Without `localhost` that version fails its own healthcheck, and Traefik won't route to an unhealthy container. 0.4.1-alpha fixes this.

## 3. Start it

```bash
cd /opt/panelarr
docker compose up -d
docker ps --filter name=panelarr   # wait for "(healthy)"
```

If Saltbox's `ddns` container is enabled, it creates the DNS record for `panelarr.example.com` on its own. If it isn't, add the record the same way you did for your other subdomains.

## 4. Run setup

1. Open `https://panelarr.example.com` and sign in through Authelia.
2. In the wizard, choose **Reverse Proxy** as the sign-in method. Panelarr detects Authelia's `Remote-User` header. It then trusts the address of the Traefik container the request came from, and the hostname you used.
3. On the services step, Panelarr finds the Saltbox apps by container name. Use these addresses:

| App | URL | Notes |
|---|---|---|
| Sonarr | `http://sonarr:8989` | API key: Sonarr → Settings → General |
| Radarr | `http://radarr:7878` | API key: Radarr → Settings → General |
| SABnzbd | `http://sabnzbd:8080` | API key: SABnzbd → Config → General |
| Plex | `http://plex:32400` | Needs a Plex token |
| qBittorrent | `http://qbittorrent:8080` | Saltbox runs it inside the `gluetun` VPN container; `qbittorrent` is that container's alias on the `saltbox` network |

A service with a URL but no key or token shows as not configured. Add the key later under Settings.

## Without Authelia

Remove `,authelia@docker` from both `panelarr-http` and `panelarr` middlewares, and choose **Username & Password** in the wizard instead of Reverse Proxy. You can drop the `panelarr-feed` router too: the feed's token is checked either way.

## When Traefik is recreated

In Reverse Proxy mode, Panelarr only accepts `Remote-User` from Traefik's exact container address. That address is assigned by Docker, so it can change when Traefik is recreated (for example by `sb install traefik`). When it does, every request answers `401 Authentication required`, and Panelarr's log says which address sent the header.

To get back in, pin Traefik's new address:

```bash
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' traefik
```

Add it to the `environment:` list in `/opt/panelarr/docker-compose.yml`, then run `docker compose up -d`:

```yaml
      - PANELARR_TRUSTED_PROXIES=172.19.0.11/32
```

Don't trust the whole `saltbox` network instead. Every Saltbox app is on it, so any of them could then send `Remote-User` and sign in as you. A durable fix is tracked in [#11](https://github.com/syms-dev/panelarr/issues/11).

## Updating

`sb update` doesn't touch Panelarr. Update it from its own folder:

```bash
cd /opt/panelarr
docker compose pull
docker compose up -d
```
