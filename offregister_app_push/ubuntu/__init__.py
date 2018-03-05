from cStringIO import StringIO
from itertools import imap, chain
from sys import modules
from functools import partial
from pkg_resources import resource_filename
from os import path

from fabric.operations import run, _run_command, sudo, put, get
from fabric.contrib.files import exists, upload_template, append
from fabric.context_managers import cd, shell_env

from offregister_fab_utils.ubuntu.systemd import restart_systemd, install_upgrade_service

from offutils import it_consumes

from offregister_fab_utils.apt import apt_depends
from offregister_fab_utils.fs import cmd_avail
from offregister_fab_utils.git import clone_or_update

from offregister_node.ubuntu import install_node0, install_global_npm_packages1

from offregister_app_push import get_logger

logger = get_logger(modules[__name__].__name__)


def push0(**kwargs):
    apt_depends('git')

    destroy_node_modules = kwargs.get('destroy_node_modules', True)
    nm = '{}/{}'.format(kwargs['GIT_DIR'], 'node_modules')
    if not destroy_node_modules and exists(nm):
        sudo('cp -r "{nm}" /tmp/node_modules'.format(nm=nm))  # TODO: get new temp dir

    clone_or_update(repo=kwargs['GIT_REPO'], to_dir=kwargs['GIT_DIR'], use_sudo=kwargs.get('use_sudo', False),
                    branch=kwargs.get('GIT_BRANCH', 'master'), skip_reset=kwargs.get('skip_reset', False))
    run_cmd = partial(_run_command, sudo=kwargs.get('use_sudo', False))
    user = run_cmd('echo $USER', quiet=True)
    nonroot = run('echo $USER', quiet=True)
    run_cmd('mkdir -p \'{GIT_DIR}\''.format(GIT_DIR=kwargs['GIT_DIR']))

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
                run_cmd('cp -r /tmp/node_modules "{nm}"'.format(nm=nm))
                run_cmd('rm -rf /tmp/node_modules')

            if run_cmd('npm i --unsafe-perm=true', warn_only=True).failed:
                # sudo('chown -R {user} {npm_tmp}'.format(user=user, npm_tmp=npm_tmp))
                run_cmd('chown -R {u} {d} {s}'.format(u=nonroot, d=kwargs['GIT_DIR'],
                                                  s='$(npm config get prefix)/{lib/node_modules,bin,share}',))
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

            home_dir = run('echo $HOME', quiet=True)
            curr_dir = run('echo "${PWD##*/}"')

            if kwargs['RDBMS_URI']:
                rdbms_uri = kwargs['RDBMS_URI'] if isinstance(kwargs['RDBMS_URI'], basestring) \
                    else ''.join(imap(str, kwargs['RDBMS_URI']))
            else:
                rdbms_uri = run('echo "$RDBMS_URI"')

            kwargs['Environments'] = '{}\n'.format(kwargs['Environments']) if 'Environments' in kwargs else ''
            kwargs['Environments'] += 'Environment=RDBMS_URI={rdbms_uri}\n' \
                                      'Environment=PORT={port}\n'.format(rdbms_uri=rdbms_uri,
                                                                         port=kwargs['REST_API_PORT'])
            if 'DAEMON_ENV' in kwargs and kwargs['DAEMON_ENV']:
                kwargs['Environments'] += '\n'.join('Environment={k}={v}'.format(k=k, v=v)
                                                    for k, v in kwargs['DAEMON_ENV'].iteritems()
                                                    if not k.startswith('$$'))
                if "$$ENV_JSON_FILE" in kwargs['DAEMON_ENV']:
                    kwargs['Environments'] += '\n' + run(
                        "node -e 'e=require(" + '`{fname}`'.format(
                            fname=kwargs['DAEMON_ENV']['$$ENV_JSON_FILE']
                        ) + "); Object.keys(e).forEach(k => k.startsWith('$$') || console.info(`Environment=${k}=${e[k]}`))'",
                        shell_escape=False, shell=False
                    )
            kwargs['WorkingDirectory'] = kwargs['GIT_DIR']
            kwargs['ExecStart'] = kwargs['ExecStart'].format(home_dir=home_dir)
            kwargs['service_name'] = curr_dir
            kwargs['User'] = kwargs['User'] if 'User' in kwargs else 'root'
            kwargs['Group'] = kwargs['Group'] if 'Group' in kwargs else 'root'
            _install_upgrade_service(**kwargs)


def _indent(text, amount, ch=' '):
    padding = amount * ch
    return ''.join(padding + line for line in text.splitlines(True))


def nginx1(*args, **kwargs):
    if not kwargs['nginx']:
        return 'skipping nginx'

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


def _send_nginx_conf(conf_remote_filename, proxy_block_local_filepath, sites_avail_local_filepath, conf_vars):
    context = {'NGINX_PORT': conf_vars['NGINX_PORT'],
               'DNS_NAMES': ' '.join(conf_vars['DNS_NAMES']),
               'DESCRIPTION': conf_vars['DESCRIPTION'],
               'WWWPATH': conf_vars['WWWPATH'],
               'WWWROOT': conf_vars['WWWROOT'],
               'EXTRA_BLOCKS': '{}\n'.format(conf_vars['EXTRA_BLOCKS']) if 'EXTRA_BLOCKS' in conf_vars else ''}

    if proxy_block_local_filepath is not None and 'PROXY_ROUTE' in conf_vars and 'PROXY_PASS' in conf_vars:
        with open(proxy_block_local_filepath, 'rt') as f:
            context['PROXY_BLOCKS'] = _indent(f.read() % {'PROXY_ROUTE': conf_vars['PROXY_ROUTE'],
                                                          'PROXY_PASS': conf_vars['PROXY_PASS']}, 4)
    else:
        context['PROXY_BLOCKS'] = '    # No proxy blocks'

    return upload_template(sites_avail_local_filepath, conf_remote_filename,
                           context=context, use_sudo=True, backup=False)


def nginx_secure2(*args, **kwargs):
    if 'nginx_secure' in kwargs and kwargs['nginx_secure'] is not None:
        if kwargs['nginx_secure'] not in ('certbot', 'letsencrypt'):
            raise NotImplementedError('{} for nginx_secure'.format(kwargs['nginx_secure']))

        return _nginx_cerbot_setup(domains='all', https_cert_email=kwargs['https_cert_email'])


def _nginx_cerbot_setup(domains, https_cert_email, conf_dirs=('/etc/nginx/sites-enabled',),
                        use_sudo=True, warn_only=True, quiet=True):
    if not cmd_avail('certbot'):
        apt_depends('software-properties-common')
        sudo('add-apt-repository -y ppa:certbot/certbot')
        apt_depends('python-certbot-nginx')

    if domains != 'all':
        raise NotImplementedError('{} for domains'.format(domains))

    run_cmd = partial(_run_command, sudo=use_sudo, warn_only=warn_only, quiet=quiet)

    server_names_t = tuple(chain(*(run_cmd("grep -RF server_name '{conf_dir}'".format(conf_dir=conf_dir)).split('\n')
                                   for conf_dir in conf_dirs)))

    hosts = tuple(l.partition('127.0.0.1')[2].strip()
                  for l in run_cmd('grep -F 127.0.0.1 /etc/hosts').split('\n')
                  if 'localhost' not in l)

    server_names_d = dict(
        (lambda spl: (spl[1].lstrip().rstrip('; \t\r'), spl[0][:spl[0].rfind(':')]))(l.split('server_name'))
        for l in server_names_t)
    if len(server_names_d) < len(server_names_t):
        raise NotImplementedError('Same server_name in multiple files. We don\'t know what to stop!')

    hosts_d = {host: server_names_d[host] for host in hosts
               if host.count('.') > 1 and host in server_names_d and len(host.translate(None, '~^|()?*')) == len(host)}

    if not hosts_d:
        return 'hosts_d is empty empty; skipping'

    run_cmd('mkdir -p /etc/nginx/sites-disabled')
    sites_avail_local_filepath = resource_filename('offregister_app_push',
                                                   path.join('conf', 'nginx.sites-available.conf'))

    def certbot_prep(dns_name, conf_loc):
        run_cmd("mv '{}' '/etc/nginx/sites-disabled/{}'".format(conf_loc, path.split(conf_loc)[1]))
        wwwroot = '/var/www/static/{dns_name}'.format(dns_name=dns_name)
        run_cmd("rm -r '{wwwroot}'".format(wwwroot=wwwroot))
        run_cmd("mkdir '{wwwroot}'".format(wwwroot=wwwroot))
        _send_nginx_conf(conf_remote_filename='/etc/nginx/sites-enabled/{dns_name}-certbot'.format(dns_name=dns_name),
                         sites_avail_local_filepath=sites_avail_local_filepath,
                         proxy_block_local_filepath=None,
                         conf_vars={'NGINX_PORT': 80,
                                    'DNS_NAMES': (dns_name,),
                                    'DESCRIPTION': 'Temporary conf doing certbot for {}'.format(dns_name),
                                    'WWWPATH': '/',
                                    'WWWROOT': wwwroot})
        print 'one("{}", "{}") ='.format(dns_name, conf_loc), "-w '{wwwroot}' -d '{dns_name}' ".format(
            dns_name=dns_name, wwwroot=wwwroot)
        return "-w '{wwwroot}' -d '{dns_name}' ".format(dns_name=dns_name, wwwroot=wwwroot)

    secured_already = frozenset(run_cmd('ls /etc/letsencrypt/live').splitlines())
    cerbot_cmds = tuple(
        'certbot certonly --agree-tos -m {https_cert_email} --webroot {root}'.format(https_cert_email=https_cert_email,
                                                                                     root=certbot_prep(dns_name,
                                                                                                       conf_loc))
        for dns_name, conf_loc in hosts_d.iteritems()
        if dns_name not in secured_already
    )

    if not cerbot_cmds:
        return 'You must\'ve already secured all your domains. Otherwise clean: /etc/letsencrypt/live'

    service_name = 'nginx'
    if sudo('systemctl status -q {service_name} --no-pager --full'.format(service_name=service_name),
            warn_only=True).failed:
        sudo('systemctl start -q {service_name} --no-pager --full'.format(service_name=service_name))
    else:
        sudo('systemctl reload -q {service_name} --no-pager --full'.format(service_name=service_name))
    print 'cerbot_cmds =', cerbot_cmds
    certbot_res = tuple(imap(run_cmd, cerbot_cmds))
    sudo('cp /etc/nginx/sites-disabled/* /etc/nginx/sites-enabled')

    # sudo('rm -r /etc/nginx/sites-disabled')

    def secure_conf(dns_name, conf_loc, https_header):
        # print 'secure_conf({!r}, {!r})'.format(dns_name, conf_loc)
        if run_cmd('grep -Fq 443 {conf_loc}'.format(conf_loc=conf_loc)).failed:
            logger.warning('Skipping {conf_loc}; 443 already found within'.format(conf_loc=conf_loc))
        sio = StringIO()
        get(remote_path=conf_loc, use_sudo=use_sudo, local_path=sio)
        sio.seek(0)
        sio_s = sio.read()
        substr = sio_s[
                 sio_s.find('{', sio_s.find('server')):
                 sio_s.rfind('}') + 2].replace('listen 80', 'listen 443', 1)
        https_header %= {'CA_CERT_PATH': '/etc/letsencrypt/live/{dns_name}/fullchain.pem'.format(dns_name=dns_name),
                         'PRIV_KEY_PATH': '/etc/letsencrypt/live/{dns_name}/privkey.pem'.format(dns_name=dns_name)}

        ''' # TODO: Address parsing, if not in `listen` keyword
        sni = substr.find('server_name')
        sni = substr[sni:substr.find(';', sni)]
        col = sni.rfind(':')
        col = col.format(':') if col > -1 else col'''

        return put(remote_path=conf_loc, use_sudo=use_sudo,
                   local_path=StringIO('{orig}\n\nserver {substr}'.format(orig=sio_s,
                                                                          substr=substr.replace(
                                                                              '{dns_name};\n'.format(dns_name=dns_name),
                                                                              '{dns_name};\n{https_header}\n'.format(
                                                                                  dns_name=dns_name,
                                                                                  https_header=_indent(https_header,
                                                                                                       4)),
                                                                              1))))

    with open(resource_filename('offregister_app_push',
                                path.join('conf', 'nginx.https_header.conf')), 'rt') as f:
        https_header = f.read()
    replaced_confs = tuple(secure_conf(dns_name, conf_loc, https_header) for dns_name, conf_loc in hosts_d.iteritems())

    sudo('systemctl reload -q {service_name} --no-pager --full'.format(service_name=service_name))
    return {'certbot_res': certbot_res, 'replaced_confs': replaced_confs}


def _install_upgrade_service(service_name, **kwargs):
    install_upgrade_service(service_name,
                            conf_local_filepath=kwargs.get('systemd-conf-file'),
                            context={
                                'ExecStart': kwargs['ExecStart'], 'Environments': kwargs['Environments'],
                                'WorkingDirectory': kwargs['WorkingDirectory'],
                                'User': kwargs['User'], 'Group': kwargs['Group'],
                                'service_name': service_name})
    return restart_systemd(service_name)
