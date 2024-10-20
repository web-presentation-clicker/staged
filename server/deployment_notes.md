# deployment
These notes are developed for and tested on Debian 12 Linux

## dependencies
depending on your distro, these may vary
```bash
sudo apt install python3 python3-venv nginx build-essential python3-dev libpcre3 libpcre3-dev libssl-dev
```

## setting up environment
we need a python virtual environment with uwsgi

### daemon user
to practice rule of least privilege, we must run the stage daemon as an unprivileged user account.
rumor has it, if you run staged as root, a uwsgi developer will emerge from the bushes to scold you (and rightfully so). 
```bash
sudo useradd -d /opt/staged -rUMs /bin/false staged
```
breakdown:
- `-d /opt/staged`: home directory of `/opt/staged`
- `-r`: make the account a system account (this reduces privileges)
- `-U`: also create group with same name, "staged"
- `-M`: don't create the home directory (it will be made later)
- `-s /bin/false`: sets the login shell to `/bin/false` (this prevents logging in over ssh and other similar attacks)
- `staged`: the username is staged

### update user
once again following the rule of least privilege, create a user for updating staged. staged should not update itself, and this avoids updating it as root.
```bash
sudo useradd -d /opt/staged -g staged -rNMs /bin/false stagedupd
```
breakdown:
- `-d /opt/staged`: home directory of `/opt/staged`
- `-g staged`: make user a member of the staged group
- `-r`: make the account a system account
- `-N`: don't create group with same name
- `-M`: don't create the home directory
- `-s /bin/false`: sets the login shell to `/bin/false`
- `stagedupd`: the username is stagedupd

### file structure
I am paranoid, so I like my filesystem permissions tight and restricted.
```bash
sudo mkdir -p /opt/staged
sudo chown -R stagedupd:staged /opt/staged
sudo chmod -R 0750 /opt/staged
```
this creates `/opt/staged`, owned by stagedupd and readable by the staged group.
the idea is that stagedupd can update staged, but staged cannot update itself. there is no legitimate reason for a webserver to modify its own code/binary while serving requests.

### python virtual environment
this next part will need to happen while logged in as stagedupd. you can do this with sudo, since normally logging in won't work.
```bash
sudo -u stagedupd bash
cd ~
```

now, create the virtual environment in `/opt/staged/venv`
```bash
python3 -m venv venv
```

## install the daemon
### download
todo

placeholder destination: downloaded

```bash
mv downloaded app
```

### install requirements
activate the venv
```bash
source venv/bin/activate
```
install wheel and the requirements from requirements.txt
```bash
pip install wheel
pip install -r app/requirements.txt

# optional: install prometheus-client for prometheus exporting
pip install prometheus-client
```

### configure
use the default configurations as a base:
```bash
cp app/extras/example_config.yml config.yml
cp app/extras/staged.ini staged.ini
```
- `config.yml`: this is the configuration for staged, and is shared between the session server and the uwsgi app. the defaults should work fine
- `staged.ini`: this is the configuration for uwsgi, it is recommended to tweak this until you find the optimal settings for your system

### systemd service
we are done with the stagedupd user, so press ctrl+D or type `exit` to go back to your normal user.

use the included systemd unit, it includes some extra hardening configurations that limit the capabilities of the daemon. 
```bash
sudo cp /opt/staged/app/extras/staged.service /etc/systemd/system/staged.service
sudo systemctl daemon-reload
```

start the service and check on it:
```bash
sudo systemctl enable --now staged.service

# check status
sudo systemctl status staged.service

# monitor logs
sudo journalctl -efu staged.service
# monitor logs, but with colors
sudo journalctl -efu staged.service --output=cat
```

**make sure you read these logs, especially on first run. you MUST correct any errors before putting in production**

### other systemd service
~~when I figure out how to attach this daemon to the uwsgi app, this won't be needed.~~

this needs to be included as a second service (todo: finish these docs)
```bash
cat << 'EOF' | sudo tee /etc/systemd/system/staged-sessionserver.service
[Unit]
Description=staged session server
After=network-online.target

[Service]
User=staged
Group=staged
RuntimeDirectory=staged
RuntimeDirectoryPreserve=yes
WorkingDirectory=/opt/staged/app
ExecStart=/opt/staged/venv/bin/python -u /opt/staged/app/sessionserver.py
Restart=on-failure
KillMode=process

PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
PrivateDevices=true
NoNewPrivileges=true
CapabilityBoundingSet=~CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
```

start the service and verify that it didn't just explode:
```bash
sudo systemctl enable --now staged-sessionserver.service

# check status
sudo systemctl status staged-sessionserver.service

# monitor logs
sudo journalctl -efu staged-sessionserver.service
# monitor logs, but with colors
sudo journalctl -efu staged-sessionserver.service --output=cat
```

## nginx
for now, only nginx is supported. see uwsgi docs for using anything else

copy the example
```bash
sudo cp /opt/staged/app/extras/staged.nginx-sample /etc/nginx/sites-available/staged
```

edit it. you need to at least change server_name to point to your domain, and you should also configure ssl
```bash
sudo vim /etc/nginx/sites-available/staged
```

enable site configuration
```bash
sudo ln -s /etc/nginx/sites-available/staged /etc/nginx/sites-enabled
```

validate config and reload nginx
```bash
sudo nginx -t && sudo systemctl reload nginx
```

your instance should now be accessible on the Internet

