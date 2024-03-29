from __future__ import print_function

from sys import modules, version

from offregister_certbot.shared import install
from offutils.util import iteritems

if version[0] == "2":
    from itertools import imap as map

    try:
        from cStringIO import StringIO
    except ImportError:
        from StringIO import StringIO
else:
    from io import StringIO

from itertools import chain
from os import path

from fabric.contrib.files import exists
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.ubuntu.systemd import (
    install_upgrade_service,
    restart_systemd,
)
from pkg_resources import resource_filename

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def _indent(text, amount, ch=" "):
    padding = amount * ch
    return "".join(padding + line for line in text.splitlines(True))


def _send_nginx_conf(
    conf_remote_filename,
    proxy_block_local_filepath,
    sites_avail_local_filepath,
    conf_vars,
):
    context = {
        "NGINX_PORT": conf_vars["NGINX_PORT"],
        "DNS_NAMES": " ".join(conf_vars["DNS_NAMES"]),
        "DESCRIPTION": conf_vars["DESCRIPTION"],
        "WWWPATH": conf_vars["WWWPATH"],
        "WWWROOT": conf_vars["WWWROOT"],
        "EXTRA_BLOCKS": "{}\n".format(conf_vars["EXTRA_BLOCKS"])
        if "EXTRA_BLOCKS" in conf_vars
        else "",
    }

    if (
        proxy_block_local_filepath is not None
        and "PROXY_ROUTE" in conf_vars
        and "PROXY_PASS" in conf_vars
    ):
        with open(proxy_block_local_filepath, "rt") as f:
            context["PROXY_BLOCKS"] = _indent(
                f.read()
                % {
                    "PROXY_ROUTE": conf_vars["PROXY_ROUTE"],
                    "PROXY_PASS": conf_vars["PROXY_PASS"],
                },
                4,
            )
    else:
        context["PROXY_BLOCKS"] = "    # No proxy blocks"

    return upload_template_fmt(
        c,
        sites_avail_local_filepath,
        conf_remote_filename,
        context=context,
        use_sudo=True,
        backup=False,
    )


def _nginx_cerbot_setup(
    domains,
    https_cert_email,
    conf_dirs=("/etc/nginx/sites-enabled",),
    use_sudo=True,
    warn=True,
    hide=True,
):
    if not cmd_avail(c, "certbot"):
        install()

    if domains != "all":
        raise NotImplementedError("{} for domains".format(domains))

    run_cmd = c.sudo if kwargs.get("use_sudo", False) else c.run

    if not c.run(
        "ls -A '{conf_dir}'".format(conf_dir=conf_dirs[0]), shell_escape=False
    ):
        return "hosts_d is empty empty; skipping"

    server_names_t = tuple(
        chain(
            *(
                run_cmd(
                    "grep -RF server_name '{conf_dir}'".format(conf_dir=conf_dir)
                ).split("\n")
                for conf_dir in conf_dirs
            )
        )
    )

    hosts = tuple(
        l.partition("127.0.0.1")[2].strip()
        for l in run_cmd("grep -F 127.0.0.1 /etc/hosts").split("\n")
        if "localhost" not in l
    )

    server_names_d = dict(
        (lambda spl: (spl[1].lstrip().rstrip("; \t\r"), spl[0][: spl[0].rfind(":")]))(
            l.split("server_name")
        )
        for l in server_names_t
    )
    if len(server_names_d) < len(server_names_t):
        raise NotImplementedError(
            "Same server_name in multiple files. We don't know what to stop!"
        )

    hosts_d = {
        host: server_names_d[host]
        for host in hosts
        if host.count(".") > 1
        and host in server_names_d
        and len(host.translate(None, "~^|()?*")) == len(host)
    }

    if not hosts_d:
        return "hosts_d is empty empty; skipping"

    run_cmd("mkdir -p /etc/nginx/sites-disabled")
    sites_avail_local_filepath = resource_filename(
        "offregister_app_push", path.join("conf", "nginx.sites-available.conf")
    )

    def certbot_prep(dns_name, conf_loc):
        run_cmd(
            "mv '{}' '/etc/nginx/sites-disabled/{}'".format(
                conf_loc, path.split(conf_loc)[1]
            )
        )
        wwwroot = "/var/www/static/{dns_name}".format(dns_name=dns_name)
        if exists(c, runner=c.run, path=wwwroot):
            run_cmd("rm -r '{wwwroot}'".format(wwwroot=wwwroot))
        run_cmd("mkdir -p '{wwwroot}'".format(wwwroot=wwwroot))
        _send_nginx_conf(
            conf_remote_filename="/etc/nginx/sites-enabled/{dns_name}-certbot".format(
                dns_name=dns_name
            ),
            sites_avail_local_filepath=sites_avail_local_filepath,
            proxy_block_local_filepath=None,
            conf_vars={
                "NGINX_PORT": 80,
                "DNS_NAMES": (dns_name,),
                "DESCRIPTION": "Temporary conf doing certbot for {}".format(dns_name),
                "WWWPATH": "/",
                "WWWROOT": wwwroot,
            },
        )
        print(
            'one("{}", "{}") ='.format(dns_name, conf_loc),
            "-w '{wwwroot}' -d '{dns_name}' ".format(
                dns_name=dns_name, wwwroot=wwwroot
            ),
        )
        return "-w '{wwwroot}' -d '{dns_name}' ".format(
            dns_name=dns_name, wwwroot=wwwroot
        )

    secured_already = (
        frozenset(run_cmd("ls /etc/letsencrypt/live", warn=True).splitlines())
        if exists(c, runner=c.run, path="/etc/letsencrypt/live")
        else tuple()
    )
    cerbot_cmds = tuple(
        "certbot certonly --agree-tos -m {https_cert_email} --webroot {root}".format(
            https_cert_email=https_cert_email, root=certbot_prep(dns_name, conf_loc)
        )
        for dns_name, conf_loc in iteritems(hosts_d)
        if dns_name not in secured_already
    )

    if not cerbot_cmds:
        return "You must've already secured all your domains. Otherwise clean: /etc/letsencrypt/live"

    service_name = "nginx"
    if (
        c.sudo(
            "systemctl status -q {service_name} --no-pager --full".format(
                service_name=service_name
            ),
            warn=True,
        ).exited
        != 0
    ):
        c.sudo(
            "systemctl start -q {service_name} --no-pager --full".format(
                service_name=service_name
            )
        )
    else:
        c.sudo(
            "systemctl reload -q {service_name} --no-pager --full".format(
                service_name=service_name
            )
        )
    print("cerbot_cmds =", cerbot_cmds)
    certbot_res = tuple(map(run_cmd, cerbot_cmds))
    c.sudo("cp /etc/nginx/sites-disabled/* /etc/nginx/sites-enabled")

    # c.sudo('rm -r /etc/nginx/sites-disabled')

    def secure_conf(dns_name, conf_loc, https_header):
        # print 'secure_conf({!r}, {!r})'.format(dns_name, conf_loc)
        if (
            run_cmd(
                "grep -Fq 443 {conf_loc}".format(conf_loc=conf_loc), warn=True
            ).exited
            != 0
        ):
            logger.warning(
                "Skipping {conf_loc}; 443 already found within".format(
                    conf_loc=conf_loc
                )
            )
        sio = StringIO()
        c.get(remote=conf_loc, use_sudo=use_sudo, local=sio)
        sio.seek(0)
        sio_s = sio.read()
        substr = sio_s[
            sio_s.find("{", sio_s.find("server")) : sio_s.rfind("}") + 2
        ].replace("listen 80", "listen 443", 1)
        https_header %= {
            "CA_CERT_PATH": "/etc/letsencrypt/live/{dns_name}/fullchain.pem".format(
                dns_name=dns_name
            ),
            "PRIV_KEY_PATH": "/etc/letsencrypt/live/{dns_name}/privkey.pem".format(
                dns_name=dns_name
            ),
        }

        """ # TODO: Address parsing, if not in `listen` keyword
        sni = substr.find('server_name')
        sni = substr[sni:substr.find(';', sni)]
        col = sni.rfind(':')
        col = col.format(':') if col > -1 else col"""

        return c.put(
            remote=conf_loc,
            use_sudo=use_sudo,
            local=StringIO(
                "{orig}\n\nserver {substr}".format(
                    orig=sio_s,
                    substr=substr.replace(
                        "{dns_name};\n".format(dns_name=dns_name),
                        "{dns_name};\n{https_header}\n".format(
                            dns_name=dns_name, https_header=_indent(https_header, 4)
                        ),
                        1,
                    ),
                )
            ),
        )

    with open(
        resource_filename(
            "offregister_app_push", path.join("conf", "nginx.https_header.conf")
        ),
        "rt",
    ) as f:
        https_header = f.read()
    replaced_confs = tuple(
        secure_conf(dns_name, conf_loc, https_header)
        for dns_name, conf_loc in iteritems(hosts_d)
    )

    c.sudo(
        "systemctl reload -q {service_name} --no-pager --full".format(
            service_name=service_name
        )
    )
    return {"certbot_res": certbot_res, "replaced_confs": replaced_confs}


def _install_upgrade_service(c, service_name, **kwargs):
    install_upgrade_service(
        c,
        service_name,
        conf_local_filepath=kwargs.get("systemd-conf-file"),
        context={
            "ExecStart": kwargs["ExecStart"],
            "Environments": kwargs["Environments"],
            "WorkingDirectory": kwargs["WorkingDirectory"],
            "User": kwargs["User"],
            "Group": kwargs["Group"],
            "service_name": service_name,
        },
    )
    return restart_systemd(c, service_name)


def _environment(kwargs):
    home_dir = c.run("echo $HOME", hide=True).stdout.rstrip()

    kwargs["WorkingDirectory"] = kwargs["GIT_DIR"]

    if "{home}" in kwargs["ExecStart"]:
        kwargs["ExecStart"] = kwargs["ExecStart"].format(home_dir=home_dir)
    kwargs["service_name"] = kwargs["GIT_DIR"][kwargs["GIT_DIR"].rfind("/") + 1 :]
    kwargs["User"] = kwargs["User"] if "User" in kwargs else "root"
    kwargs["Group"] = kwargs["Group"] if "Group" in kwargs else "root"

    if kwargs["RDBMS_URI"]:
        rdbms_uri = (
            kwargs["RDBMS_URI"]
            if isinstance(kwargs["RDBMS_URI"], str)
            else "".join(map(str, kwargs["RDBMS_URI"]))
        )
    else:
        rdbms_uri = c.run('echo "$RDBMS_URI"').stdout.rstrip()

    kwargs["Environments"] = (
        "{}\n".format(kwargs["Environments"]) if "Environments" in kwargs else ""
    )
    kwargs[
        "Environments"
    ] += "Environment='RDBMS_URI={rdbms_uri}'\n" "Environment=PORT={port}\n".format(
        rdbms_uri=rdbms_uri, port=kwargs["REST_API_PORT"]
    )
    if "DAEMON_ENV" in kwargs and kwargs["DAEMON_ENV"]:
        kwargs["Environments"] += "\n".join(
            "Environment='{k}={v}'".format(k=k, v=v)
            for k, v in iteritems(kwargs["DAEMON_ENV"])
            if not k.startswith("$$")
        )
        if "$$ENV_JSON_FILE" in kwargs["DAEMON_ENV"]:
            kwargs["Environments"] += "\n" + c.run(
                """python -c 'import json; f=open("{fname}");{rest}""".format(
                    fname=kwargs["DAEMON_ENV"]["$$ENV_JSON_FILE"],
                    rest='d=json.load(f);print chr(10).join("Environment={q}{k}={v}{q}".format(q=chr(39), k=k, v=v) for k,v in d.iteritems()); f.close()\'',
                )
            )

    return kwargs
