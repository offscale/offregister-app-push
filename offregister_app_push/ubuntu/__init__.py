from itertools import imap
from sys import modules
from functools import partial
from pkg_resources import resource_filename
from os import path

from fabric.operations import run, _run_command, sudo
from fabric.contrib.files import exists, append
from fabric.context_managers import cd, shell_env

from offregister_fab_utils.ubuntu.systemd import restart_systemd

from offutils import it_consumes

from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.git import clone_or_update

from offregister_node.ubuntu import install_node0, install_global_npm_packages1

from offregister_app_push import get_logger
from offregister_app_push.ubuntu.utils import _install_upgrade_service, _send_nginx_conf, _nginx_cerbot_setup, \
    _environment

logger = get_logger(modules[__name__].__name__)

gnm = '/node_modules'


def pull0(destroy_node_modules=True, **kwargs):
    apt_depends('git')

    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))
    run_cmd('mkdir -p \'{GIT_DIR}\''.format(GIT_DIR=kwargs['GIT_DIR']))

    global gnm

    if len(gnm) != len('/node_modules'):
        gnm = '{git_dir}/{gnm}'.format(git_dir=kwargs['GIT_DIR'], gnm=gnm)

    if not destroy_node_modules and exists(gnm):
        sudo('cp -r "{nm}" /tmp/node_modules'.format(nm=gnm))  # TODO: get new temp dir

    clone_or_update(repo=kwargs['GIT_REPO'], to_dir=kwargs['GIT_DIR'], use_sudo=kwargs.get('use_sudo', False),
                    branch=kwargs.get('GIT_BRANCH', 'master'), skip_reset=kwargs.get('skip_reset', False),
                    cmd_runner=run_cmd)

    return '[git] Updated'


def node1(destroy_node_modules=True, **kwargs):
    # TODO: Split this up into multiple environments: node, docker, python, ruby, scala &etc.
    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))
    user = run_cmd('echo $USER', quiet=True)
    nonroot = run('echo $USER', quiet=True)

    if not exists('$HOME/n/bin'):
        install_node0(node_version=kwargs.get('node_version'), use_sudo=False, node_sudo=False)
    with cd(kwargs['GIT_DIR']), shell_env(PATH='$HOME/n/bin:$PATH'):
        if exists('package.json'):
            if not cmd_avail('npm'):
                logger.warn('npm not installed; skipping')
                return

            npm_tmp = run_cmd('echo $HOME/.npm/_cacache/tmp', quiet=True)
            install_global_npm_packages1(npm_global_packages=kwargs.get('npm_global_packages'),
                                         use_sudo=False, node_sudo=False)

            if destroy_node_modules:
                run_cmd('rm -rf node_modules')
            elif exists('/tmp/node_modules'):
                global gnm

                if len(gnm) != len('/node_modules'):
                    gnm = '{git_dir}/{gnm}'.format(git_dir=kwargs['GIT_DIR'], gnm=gnm)
                run_cmd('cp -r /tmp/node_modules "{nm}"'.format(nm=gnm))
                run_cmd('rm -rf /tmp/node_modules')

            if run_cmd('npm i --unsafe-perm=true', warn_only=True).failed:
                # sudo('chown -R {user} {npm_tmp}'.format(user=user, npm_tmp=npm_tmp))
                run_cmd('chown -R {u} {d} {s}'.format(u=nonroot, d=kwargs['GIT_DIR'],
                                                      s='$(npm config get prefix)/{lib/node_modules,bin,share}', ))
                sudo('npm i --unsafe-perm=true', user=nonroot)
            if exists('typings.json'):
                if cmd_avail('typings'):
                    run_cmd('rm -rf typings')
                    run_cmd('typings i')
                else:
                    logger.warn('typings not installed; skipping')
            if kwargs.get('post_npm_step'):
                run_cmd(kwargs['post_npm_step'])

            sudo('rm -rf {npm_tmp}'.format(npm_tmp=npm_tmp))

            return '[node] app built'


def service2(**kwargs):
    if 'ExecStart' not in kwargs:
        if 'node_main' in kwargs:
            kwargs['ExecStart'] = "/bin/bash -c 'PATH={home_dir}/n/bin:$PATH {home_dir}/n/bin/node {main}'".format(
                home_dir=run('echo $HOME', quiet=True), main=kwargs['node_main']
            )
        else:
            return "[Warn]: 'ExecStart' not in kwargs; skipping service installation"
    kwargs = _environment(kwargs)

    return _install_upgrade_service(**kwargs)


def nginx3(**kwargs):
    if not kwargs['nginx']:
        return '[Warn]: skipping nginx'

    if not cmd_avail('nginx'):
        sudo('add-apt-repository -y ppa:nginx/stable')
        apt_depends('nginx')

    # TODO: Move this to an nginx module; usable by other `offregister-` packages

    sites_avail_local_filepath = kwargs.get('nginx-sites-available',
                                            resource_filename('offregister_app_push',
                                                              path.join('conf', 'nginx.sites-available.conf')))
    proxy_block_local_filepath = kwargs.get('nginx-proxy-block',
                                            resource_filename('offregister_app_push',
                                                              path.join('conf', 'nginx.proxy_block.conf')))
    conf_remote_filename = '/etc/nginx/sites-enabled/{service_name}'.format(service_name=kwargs['app_name'])
    it_consumes(imap(lambda dns_name: append(text='127.0.0.1\t{site_name}'.format(site_name=dns_name),
                                             filename='/etc/hosts', use_sudo=True),
                     kwargs['DNS_NAMES']))

    _send_nginx_conf(conf_remote_filename, proxy_block_local_filepath, sites_avail_local_filepath, kwargs)

    return restart_systemd('nginx')


def nginx_secure4(*args, **kwargs):
    if 'nginx_secure' in kwargs and kwargs['nginx_secure'] is not None:
        if kwargs['nginx_secure'] not in ('certbot', 'letsencrypt'):
            raise NotImplementedError('{} for nginx_secure'.format(kwargs['nginx_secure']))

        return _nginx_cerbot_setup(domains='all', https_cert_email=kwargs['https_cert_email'])
