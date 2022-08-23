from sys import modules

from fabric.contrib.files import exists
from offregister_fab_utils.fs import cmd_avail
from offregister_node.ubuntu import install_global_npm_packages1, install_node0
from offregister_node.utils import install_node

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def build_node_app(kwargs, run_cmd):
    user = run_cmd("echo $USER", hide=True).stdout.rstrip()
    nonroot = c.run("echo $USER", hide=True).stdout.rstrip()
    if user != nonroot:
        logger.info('user = "{user}"; nonroot = "{user}"')

    n_prefix = kwargs.get("N_PREFIX", run_cmd("echo $HOME/n", hide=True))
    if not exists(c, runner=c.run, path="{n_prefix}/bin".format(n_prefix=n_prefix)):
        (
            install_node0
            if "Ubuntu" in c.run("uname -v").stdout.rstrip()
            else install_node
        )(
            node_version=kwargs.get("node_version"),
            use_sudo=False,
            node_sudo=False,
            N_PREFIX=n_prefix,
        )

    env = dict(PATH="$PATH:{n_prefix}/bin".format(n_prefix=n_prefix))
    if not cmd_avail(c, "npm"):
        return "[Warn]: npm not installed; skipping"
    npm_tmp = run_cmd("echo $HOME/.npm/_cacache/tmp", hide=True, env=env)
    install_global_npm_packages1(
        npm_global_packages=kwargs.get("npm_global_packages"),
        N_PREFIX=n_prefix,
        use_sudo=False,
        node_sudo=False,
    )
    if run_cmd("npm i --unsafe-perm=true", warn=True, env=env).exited != 0:
        # c.sudo('chown -R {user} {npm_tmp}'.format(user=user, npm_tmp=npm_tmp))
        run_cmd(
            "chown -R {u} {d} {s}".format(
                u=nonroot,
                d=kwargs["GIT_DIR"],
                s="$(npm config get prefix)/{lib/node_modules,bin,share}",
            ),
            env=env,
        )
        c.sudo("npm i --unsafe-perm=true", user=nonroot, env=env)
    if exists(c, runner=c.run, path="typings.json"):
        if cmd_avail(c, "typings"):
            run_cmd("rm -rf typings")
            run_cmd("typings i", env=env)
        else:
            logger.warn("typings not installed; skipping")
    if "post_npm_step" in kwargs:
        run_cmd(kwargs["post_npm_step"], env=env)
    c.sudo("rm -rf {npm_tmp}".format(npm_tmp=npm_tmp))
    return "[node] app built"
