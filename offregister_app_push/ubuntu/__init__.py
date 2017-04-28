from sys import modules
from functools import partial

from offregister_fab_utils.ubuntu.systemd import restart_systemd
from pkg_resources import resource_filename
from os import path

from fabric.operations import run, _run_command, sudo
from fabric.contrib.files import exists, upload_template
from fabric.context_managers import cd, shell_env

from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.git import clone_or_update

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def push0(**kwargs):
    apt_depends('git')

    destroy_node_modules = kwargs.get('destroy_node_modules', True)
    nm = '{}/{}'.format(kwargs['GIT_DIR'], 'node_modules')
    if not destroy_node_modules:
        if exists(nm):
            sudo('cp -r "{nm}" /tmp/node_modules'.format(nm=nm))  # TODO: get new temp dir

    clone_or_update(repo=kwargs['GIT_REPO'], to_dir=kwargs['GIT_DIR'], use_sudo=kwargs.get('use_sudo', False),
                    branch=kwargs.get('GIT_BRANCH', 'master'), skip_reset=kwargs.get('skip_reset', False))
    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))
    run_cmd('mkdir -p \'{GIT_DIR}\''.format(GIT_DIR=kwargs['GIT_DIR']))
    with cd(kwargs['GIT_DIR']), shell_env(PATH='$HOME/n/bin:$PATH'):
        if exists('package.json'):
            if cmd_avail('npm'):
                if destroy_node_modules:
                    run_cmd('rm -rf node_modules')
                else:
                    run_cmd('cp -r /tmp/node_modules "{nm}"'.format(nm=nm))
                    run_cmd('rm -rf /tmp/node_modules')
                run_cmd('npm i')
                if exists('typings.json'):
                    if cmd_avail('typings'):
                        run_cmd('rm -rf typings')
                        run_cmd('typings i')
                    else:
                        logger.warn('typings not installed; skipping')
                home_dir = run('echo $HOME', quiet=True)
                curr_dir = run('echo "${PWD##*/}"')
                rdbms_uri = run('echo "$RDBMS_URI"')
                kwargs['Environments'] = '{}\n'.format(kwargs['Environments']) if 'Environments' in kwargs else ''
                kwargs['Environments'] += 'Environment=RDBMS_URI={rdbms_uri}\n' \
                                          'Environment=PORT=8000\n'.format(rdbms_uri=rdbms_uri)
                kwargs['WorkingDirectory'] = kwargs['GIT_DIR']
                kwargs['ExecStart'] = kwargs['ExecStart'].format(home_dir=home_dir)
                kwargs['service_name'] = curr_dir
                kwargs['User'] = kwargs['User'] if 'User' in kwargs else 'root'
                kwargs['Group'] = kwargs['Group'] if 'Group' in kwargs else 'root'
                _install_upgrade_service(**kwargs)
            else:
                logger.warn('npm not installed; skipping')


def _install_upgrade_service(service_name, **kwargs):
    conf_local_filepath = kwargs.get('systemd-conf-file',
                                     resource_filename('offregister_app_push', path.join('conf', 'systemd.conf')))
    conf_remote_filename = '/lib/systemd/system/{service_name}.service'.format(service_name=service_name)
    upload_template(conf_local_filepath, conf_remote_filename,
                    context={'ExecStart': kwargs['ExecStart'], 'Environments': kwargs['Environments'],
                             'WorkingDirectory': kwargs['WorkingDirectory'],
                             'User': kwargs['User'], 'Group': kwargs['Group'],
                             'service_name': service_name},
                    use_sudo=True)
    return restart_systemd(service_name)
