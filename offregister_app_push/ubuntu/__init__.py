from collections import deque
from os import path
from sys import modules, version

from fabric.context_managers import shell_env
from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.git import clone_or_update
from offregister_fab_utils.ubuntu.systemd import restart_systemd
from patchwork.files import append, exists
from pkg_resources import resource_filename

if version[0] == "2":
    from itertools import imap as map

    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO
else:
    from io import StringIO

from offregister_app_push import get_logger
from offregister_app_push.app_builders import build_node_app
from offregister_app_push.ubuntu.utils import (
    _environment,
    _install_upgrade_service,
    _nginx_cerbot_setup,
    _send_nginx_conf,
)

logger = get_logger(modules[__name__].__name__)


def pull0(destory_cache=True, **kwargs):
    apt_depends(c, "git")

    run_cmd = c.sudo if kwargs.get("use_sudo", False) else c.run

    cache = not destory_cache and exists(c, runner=c.run, path=kwargs["GIT_DIR"])

    if cache:
        dirnam = run_cmd(
            "mktemp -d --suffix '{name}'".format(
                name=kwargs["GIT_DIR"][kwargs["GIT_DIR"].rfind("/") + 1 :]
            )
        )
        run_cmd(
            """while read -r l; do [ -e "$l" ] && mv "$l" '{dirnam}' & done <'{git_dir}/.gitignore' """.format(
                dirnam=dirnam, git_dir=kwargs["GIT_DIR"]
            )
        )

    clone_or_update(
        repo=kwargs["GIT_REPO"],
        to_dir=kwargs["GIT_DIR"],
        use_sudo=kwargs.get("use_sudo", False),
        branch=kwargs.get("GIT_BRANCH", "master"),
        skip_reset=kwargs.get("skip_reset", False),
        cmd_runner=run_cmd,
    )

    if cache:
        run_cmd(
            """while read -r l; do d="{dirnam}/$l"; [ -e "$d" ] && cp -r "$d" '{git_dir}' & done <'{git_dir}/.gitignore' """.format(
                dirnam=dirnam, git_dir=kwargs["GIT_DIR"]
            )
        )

        run_cmd("rm -rf {dirnam}".format(dirnam=dirnam))

    return "[git] Updated"


def build_app1(**kwargs):
    # TODO: Split this up into multiple environments: node, docker, python, ruby, scala &etc.
    # TODO: Read Procfile, Dockerfile and any other signature hints (like existent package.json) for this
    # TODO: Use ^ to acquire extra environment variables needed for the systemd service
    run_cmd = (
        c.sudo if kwargs.get("node_sudo", kwargs.get("use_sudo", False)) else c.run
    )

    if exists(
        c, runner=c.run, path="{git_dir}/package.json".format(git_dir=kwargs["GIT_DIR"])
    ):
        with c.cd(kwargs["GIT_DIR"]), shell_env(PATH="$HOME/n/bin:$PATH"):
            return build_node_app(run_cmd=run_cmd, kwargs=kwargs)

    return "[Warn]: Not building any app"


def service2(**kwargs):
    if "ExecStart" not in kwargs:
        if "node_main" in kwargs:
            n_prefix = kwargs.get(
                "N_PREFIX",
                (c.sudo if kwargs.get("node_sudo", kwargs.get("use_sudo")) else c.run)(
                    "echo $HOME/n",
                    hide=True,
                ).stdout,
            )
            kwargs[
                "ExecStart"
            ] = "/bin/bash -c 'PATH={n_prefix}/bin:$PATH {n_prefix}/bin/node {main}'".format(
                n_prefix=n_prefix, main=kwargs["node_main"]
            )
        else:
            return "[Warn]: 'ExecStart' not in kwargs; skipping service installation"
    kwargs = _environment(kwargs)

    return _install_upgrade_service(**kwargs)


def nginx3(**kwargs):
    if not kwargs["nginx"]:
        return "[Warn]: skipping nginx"

    if not cmd_avail(c, "nginx") and not exists(c, runner=c.run, path="/etc/nginx"):
        uname = c.run("uname -v").stdout.rstrip()
        sio = StringIO()

        flavour = None
        if "Ubuntu" in uname:
            flavour = "ubuntu"
        elif "Debian" in uname:
            flavour = "debian"
        if flavour is None:
            raise NotImplementedError()

        apt_depends(c, "curl", "gnupg2", "ca-certificates", "lsb-release")
        release = c.run("lsb_release -cs").stdout.rstrip()
        sio.write(
            "deb http://nginx.org/packages/{flavour} {release} nginx".format(
                flavour=flavour, release=release
            )
        )
        c.put(sio, "/etc/apt/sources.list.d/nginx.list", use_sudo=True)
        c.sudo("apt-get update -qq")

        c.sudo("curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -")
        c.sudo("apt-key fingerprint ABF5BD827BD9BF62")
        apt_depends(c, "nginx")

    # TODO: Move this to an nginx module; usable by other `offregister-` packages

    sites_avail_local_filepath = kwargs.get(
        "nginx-sites-available",
        resource_filename(
            "offregister_app_push", path.join("conf", "nginx.sites-available.conf")
        ),
    )
    proxy_block_local_filepath = kwargs.get(
        "nginx-proxy-block",
        resource_filename(
            "offregister_app_push", path.join("conf", "nginx.proxy_block.conf")
        ),
    )
    remote_conf_dir = "/etc/nginx/sites-enabled"
    if not exists(c, runner=c.run, path=remote_conf_dir):
        c.sudo("mkdir -p {}".format(remote_conf_dir))
        c.sudo(
            r"sed -i '/include \/etc\/nginx\/conf.d\/\*.conf;/ a\ \ \ \ include {remote_dir}/*;' {fname}".format(
                remote_dir=remote_conf_dir, fname="/etc/nginx/nginx.conf"
            )
        )

    conf_remote_filename = "/etc/nginx/sites-enabled/{service_name}.conf".format(
        service_name=kwargs["app_name"]
    )
    deque(
        map(
            lambda dns_name: append(
                c,
                text="127.0.0.1\t{site_name}".format(site_name=dns_name),
                filename="/etc/hosts",
                use_sudo=True,
            ),
            kwargs["DNS_NAMES"],
        ),
        maxlen=0,
    )

    _send_nginx_conf(
        conf_remote_filename,
        proxy_block_local_filepath,
        sites_avail_local_filepath,
        kwargs,
    )

    return restart_systemd("nginx")


def nginx_secure4(c, *args, **kwargs):
    if "nginx_secure" in kwargs and kwargs["nginx_secure"] is not None:
        if kwargs["nginx_secure"] not in ("certbot", "letsencrypt"):
            raise NotImplementedError(
                "{} for nginx_secure".format(kwargs["nginx_secure"])
            )

        return _nginx_cerbot_setup(
            domains="all", https_cert_email=kwargs["https_cert_email"]
        )
