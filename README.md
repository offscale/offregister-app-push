offregister_app_push
====================
[![No Maintenance Intended](http://unmaintained.tech/badge.svg)](http://unmaintained.tech)
![Python version range](https://img.shields.io/badge/python-2.7%20|%203.4%20|%203.5%20|%203.6%20|%203.7%20|%203.8-blue.svg)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

This package follows the offregister specification to facilitate [push] app deployments.

Currently can deploy Node.JS and static file applications. Also uses certbot to install HTTPS certificates (with nginx).

Useful for your development server. For staging, test and production tiers, recommend using this as a base to:

  1. Package OS specific (e.g.: `foo-rest-api.deb`)
  2. Make repeatable builds—using Docker or similar—but with only a few lines that just sets the OS and installs the `.deb`s  (debconf-set-selections for configurating)

For these other tiers I recommend looking into one—or more—of these free and open-source solutions:

  - [Mesosphere DC/OS](https://dcos.io)
  - [Kubernetes](https://kubernetes.io)
  - [Docker Swarm](https://docs.docker.com/engine/swarm)
  - &etc. (there are plenty of projects in this space)

These handle versioning, deploying across numbers of servers, and clustering (ensuring you always have k APIs running).
Some also handle DNS, security, canary deployments &etc.

For stateful components such as databases, look further into Mesosphere, or just using the memory grid as a cluster, or deploying the stateful systems outside this cluster and using Mesos to allocate resources between container services & stateful services.

## Install dependencies

    pip install -r requirements.txt

## Install package

    pip install .

## Example config

    {
        "module": "offregister-app-push",
        "kwargs": {
          "DAEMON_ENV": {
            "DEFAULT_ADMIN_EMAIL": {
              "$ref": "env:DEFAULT_ADMIN_EMAIL"
            },
            "DEFAULT_ADMIN_PASSWORD": {
              "$ref": "env:DEFAULT_ADMIN_PASSWORD"
            }
          },
          "GIT_DIR": "/var/www/static/stereostream-rest-api",
          "GIT_REPO": "https://github.com/stereostream/stereostream-rest-api",
          "GIT_BRANCH": "version-3",
          "service_name": "stereostream-rest-api",
          "skip_reset": false,
          "destroy_node_modules": true,
          "use_sudo": true,
          "node_sudo": false,
          "node_version": "8.9.4",
          "node_main": "main.js",
          "RDBMS_URI": [
            "postgres://",
            {
              "$ref": "env:DB_USER"
            },
            ":",
            {
              "$ref": "env:DB_PASS"
            },
            "@",
            "localhost",
            "/",
            {
              "$ref": "env:DB_NAME"
            }
          ],
          "npm_global_packages": [
            "typings",
            "mocha",
            "typescript",
            "bunyan"
          ],
          "post_npm_step": "tsc",
          "nginx": true,
          "app_name": "stereostream",
          "DESCRIPTION": "stereostream frontend and backend",
          "DNS_NAMES": [
            "stereostream.complicated.io"
          ],
          "PROXY_ROUTE": "/api",
          "PROXY_PASS": "http://localhost:5466",
          "REST_API_PORT": 5466,
          "NGINX_PORT": 80,
          "WWWROOT": "/var/www/static/stereostream-web-frontend-dist/dist",
          "WWWPATH": "/",
          "nginx_secure": "certbot",
          "https_cert_email": "samuel@offscale.io"
    }

To setup your environment to use this config, follow [the getting started guide](https://offscale.io/docs/getting-started).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
