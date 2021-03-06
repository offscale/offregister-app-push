from sys import modules

from fabric.context_managers import shell_env
from fabric.contrib.files import exists
from fabric.operations import sudo, run
from offregister_fab_utils.fs import cmd_avail
from offregister_node.ubuntu import install_node0, install_global_npm_packages1
from offregister_node.utils import install_node

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def build_node_app(kwargs, run_cmd):
    user = run_cmd("echo $USER", quiet=True)
    nonroot = run("echo $USER", quiet=True)
    if user != nonroot:
        logger.info('user = "{user}"; nonroot = "{user}"')

    n_prefix = kwargs.get("N_PREFIX", run_cmd("echo $HOME/n", quiet=True))
    if not exists("{n_prefix}/bin".format(n_prefix=n_prefix)):
        (install_node0 if "Ubuntu" in run("uname -v") else install_node)(
            node_version=kwargs.get("node_version"),
            use_sudo=False,
            node_sudo=False,
            N_PREFIX=n_prefix,
        )

    with shell_env(PATH="$PATH:{n_prefix}/bin".format(n_prefix=n_prefix)):
        if not cmd_avail("npm"):
            return "[Warn]: npm not installed; skipping"
        npm_tmp = run_cmd("echo $HOME/.npm/_cacache/tmp", quiet=True)
        install_global_npm_packages1(
            npm_global_packages=kwargs.get("npm_global_packages"),
            N_PREFIX=n_prefix,
            use_sudo=False,
            node_sudo=False,
        )
        if run_cmd("npm i --unsafe-perm=true", warn_only=True).failed:
            # sudo('chown -R {user} {npm_tmp}'.format(user=user, npm_tmp=npm_tmp))
            run_cmd(
                "chown -R {u} {d} {s}".format(
                    u=nonroot,
                    d=kwargs["GIT_DIR"],
                    s="$(npm config get prefix)/{lib/node_modules,bin,share}",
                )
            )
            sudo("npm i --unsafe-perm=true", user=nonroot)
        if exists("typings.json"):
            if cmd_avail("typings"):
                run_cmd("rm -rf typings")
                run_cmd("typings i")
            else:
                logger.warn("typings not installed; skipping")
        if "post_npm_step" in kwargs:
            run_cmd(kwargs["post_npm_step"])
        sudo("rm -rf {npm_tmp}".format(npm_tmp=npm_tmp))
        return "[node] app built"
