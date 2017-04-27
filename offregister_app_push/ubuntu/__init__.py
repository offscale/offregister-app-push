from sys import modules
from functools import partial

from fabric.operations import run, _run_command
from fabric.contrib.files import exists
from fabric.context_managers import cd

from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.git import clone_or_update

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def push0(*args, **kwargs):
    apt_depends('git')

    clone_or_update(repo=kwargs['GIT_REPO'], to_dir=kwargs['GIT_DIR'], use_sudo=kwargs.get('use_sudo', False),
                    branch=kwargs.get('GIT_BRANCH', 'master'))
    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))
    run_cmd('mkdir -p \'{GIT_DIR}\''.format(GIT_DIR=kwargs['GIT_DIR']))
    with cd(kwargs['GIT_DIR']):
        if exists('package.json'):
            if cmd_avail('npm'):
                run_cmd('rm -rf node_modules')
                run_cmd('npm i')
                if exists('typings.json'):
                    if cmd_avail('typings'):
                        run_cmd('rm -rf typings')
                        run_cmd('typings i')
                    else:
                        logger.warn('typings not installed; skipping')
            else:
                logger.warn('npm not installed; skipping')
