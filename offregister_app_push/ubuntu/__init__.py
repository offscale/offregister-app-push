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

from offregister_app_push import get_logger
from offregister_app_push.ubuntu.app_builders import build_node_app
from offregister_app_push.ubuntu.utils import _install_upgrade_service, _send_nginx_conf, _nginx_cerbot_setup, \
    _environment

logger = get_logger(modules[__name__].__name__)


def pull0(destory_cache=True, **kwargs):
    apt_depends('git')

    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))

    cache = not destory_cache and exists(kwargs['GIT_DIR'])

    if cache:
        dirnam = sudo("mktemp -d --suffix '{name}'".format(name=kwargs['GIT_DIR'][kwargs['GIT_DIR'].rfind('/') + 1:]))
        run_cmd('''while read -r l; do [ -e "$l" ] && mv "$l" '{dirnam}' & done <'{git_dir}/.gitignore' '''.format(
            dirnam=dirnam, git_dir=kwargs['GIT_DIR'])
        )
    run_cmd("mkdir -p '{GIT_DIR}'".format(GIT_DIR=kwargs['GIT_DIR']))
    clone_or_update(repo=kwargs['GIT_REPO'], to_dir=kwargs['GIT_DIR'], use_sudo=kwargs.get('use_sudo', False),
                    branch=kwargs.get('GIT_BRANCH', 'master'), skip_reset=kwargs.get('skip_reset', False),
                    cmd_runner=run_cmd)

    if cache:
        run_cmd(
            '''while read -r l; do d="{dirnam}/$l"; [ -e "$d" ] && cp -r "$d" '{git_dir}' & done <'{git_dir}/.gitignore' '''.format(
                dirnam=dirnam, git_dir=kwargs['GIT_DIR']
            )
        )

        run_cmd('rm -rf {dirnam}'.format(dirnam=dirnam))

    return '[git] Updated'


def build_app1(**kwargs):
    # TODO: Split this up into multiple environments: node, docker, python, ruby, scala &etc.
    # TODO: Read Procfile, Dockerfile and any other signature hints (like existent package.json) for this
    # TODO: Use ^ to acquire extra environment variables needed for the systemd service
    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))

    if exists('{git_dir}/package.json'.format(git_dir=kwargs['GIT_DIR'])):
        with cd(kwargs['GIT_DIR']), shell_env(PATH='$HOME/n/bin:$PATH'):
            return build_node_app(run_cmd=run_cmd, kwargs=kwargs)

    return '[Warn]: Not building any app'


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
