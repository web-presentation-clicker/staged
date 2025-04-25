# deployment
These notes are developed for and tested on Debian 12 Linux.

## dependencies
Install packages:
```bash
sudo apt install python3 python3-venv nginx build-essential python3-dev libpcre3 libpcre3-dev libssl-dev curl
```
These are needed for compiling and installing uwsgi in a virtual environment. Curl is also included because I feel like using curl.

## setting up environment
Now, we'll set up some user accounts and create that python virtual environment. 

### daemon user
To practice rule of least privilege, we must run the stage daemon as an unprivileged user account.
Rumor has it, if you run staged as root, a uWSGI developer will emerge from the bushes to scold you (and rightfully so). 
```bash
sudo useradd -d /opt/staged -rUMs /bin/false staged
```
what the flags do:
- `-d /opt/staged`: home directory of `/opt/staged`
- `-r`: make the account a system account (this reduces privileges)
- `-U`: also create group with same name, "staged"
- `-M`: don't create the home directory (it will be made later)
- `-s /bin/false`: sets the login shell to `/bin/false` (this prevents logging in over ssh and other similar attacks)
- `staged`: the username is staged

### update user
Once again following the rule of least privilege, create a user for updating staged. staged should not update itself, and this avoids updating it as root.
```bash
sudo useradd -d /opt/staged -g staged -rNMs /bin/false stagedupd
```
what the flags do:
- `-d /opt/staged`: home directory of `/opt/staged`
- `-g staged`: make user a member of the staged group
- `-r`: make the account a system account
- `-N`: don't create group with same name
- `-M`: don't create the home directory
- `-s /bin/false`: sets the login shell to `/bin/false`
- `stagedupd`: the username is stagedupd

### file structure and permissions
By this point it should be obvious that I am paranoid, so I like my filesystem permissions tight and restricted.
```bash
sudo mkdir -p /opt/staged
sudo chown -R stagedupd:staged /opt/staged
sudo chmod 0750 /opt/staged
```
This creates `/opt/staged`, owned by stagedupd and readable by the staged group.
The idea is that stagedupd can update staged, but staged cannot update itself. 
There is no legitimate reason for a webserver like this one to modify its own code/binary while serving requests.

### python virtual environment
This next part will need to happen while logged in as stagedupd. You can do this with sudo, since normally logging in won't work.
```bash
sudo -u stagedupd bash
cd ~
```

Now, create the virtual environment in `/opt/staged/venv`
```bash
python3 -m venv venv
```

## install the daemon
These are the steps for initial installation, **for updating staged, see the [updating staged](#updating-staged) section below**.

### login as stagedupd
If you haven't already logged in as stagedupd and activated the venv, do so now:
```bash
sudo -u stagedupd bash
cd ~
source ~/venv/bin/activate
```

### download
Find the latest release tarball [on the releases page](https://github.com/web-presentation-clicker/staged/releases). Download and extract it:
```bash
mkdir ~/downloaded
cd ~/downloaded

curl https://github.com/web-presentation-clicker/staged/releases/download/<VERSION CODE>/staged.tar.gz -Lo staged.tar.gz

tar -xvf staged.tar.gz
rm staged.tar.gz

cd ~
```

Copy the server directory into place:
```bash
cp -r ~/downloaded/staged/server ~/app
```

### install requirements
Install wheel and the requirements from `requirements.txt`:
```bash
pip install wheel
pip install -r ~/app/requirements.txt

# optional: install prometheus-client for prometheus exporting
pip install prometheus-client
```

### configure
Use the default configurations as a base:
```bash
cp ~/app/extras/example_config.yml ~/config.yml
cp ~/app/extras/staged.ini ~/staged.ini
```
- `config.yml`: This is the configuration for staged, and is shared between the session server and the uwsgi app. The defaults should work fine, but you may need to tweak them if you run into issues.
- `staged.ini`: This is the configuration for uWSGI, it is recommended to tweak this until you find the optimal settings for your system.

### systemd services
We are done with the stagedupd user, so press ctrl+D or type `exit` to go back to your normal user.

#### install unit files
Use the included systemd units, they include some extra hardening configurations that limit the capabilities of the daemon for security.
```bash
sudo cp /opt/staged/app/extras/staged-sessionserver.service /etc/systemd/system/staged-sessionserver.service
sudo cp /opt/staged/app/extras/staged.service /etc/systemd/system/staged.service
sudo systemctl daemon-reload
```

#### session server
This service is responsible for keeping track of all the active sessions. It's multi-threaded, and acts as a single place for all of the uWSGI processes to communicate.
Restarting it will clear all the sessions and be disruptive for users, as they will have to re-scan the QR Code to re-pair their clicker.

Enable the service:
```bash
sudo systemctl enable --now staged-sessionserver.service

# check status
sudo systemctl status staged-sessionserver.service

# to restart
sudo systemctl restart staged-sessionserver.service

# monitor logs
sudo journalctl -efu staged-sessionserver.service

# monitor logs, but with colors
sudo journalctl -efu staged-sessionserver.service --output=cat
```

#### uwsgi app
This service is responsible for handling incoming connections. It's multi-processed and can accept thousands of simultaneous connections.
Restarting it will close all active connections, but clients will automatically reconnect after a few seconds.

```bash
sudo systemctl enable --now staged.service

# check status
sudo systemctl status staged.service

# to restart
sudo systemctl restart staged.service

# monitor logs
sudo journalctl -efu staged.service

# monitor logs, but with colors
sudo journalctl -efu staged.service --output=cat
```

#### read the logs
**Make sure you read the logs, especially on first run!**

The logs are the only way staged can tell you something's broken.
Additionally, uWSGI will start and stay running even when something's broken.
```bash
sudo journalctl -efu staged-sessionserver.service --output=cat
sudo journalctl -efu staged.service --output=cat
```

### static pages
Now, copy the static pages used for the clicker into place.

```bash
sudo cp -r /opt/staged/downloaded/staged/static /var/www/staged
```

### clean up
Once you are sure everything is working, you can (optionally) delete the downloaded files.

```bash
sudo -u stagedupd rm -rf ~/downloaded/
```

## nginx
For now, only nginx is supported. See [the uWSGI docs](https://uwsgi-docs.readthedocs.io/en/latest/#web-server-support) for using anything else.

Copy the example configuration:
```bash
sudo cp /opt/staged/app/extras/staged.nginx-sample /etc/nginx/sites-available/staged
```

You will need to edit the configuration. You must at least change `server_name` to point to your domain, and you should also configure SSL.
For SSL, you may find "certbot" useful for easily/automatically renewing your SSL certificate.
```bash
sudo vim /etc/nginx/sites-available/staged
```

Enable the site configuration:
```bash
sudo ln -s /etc/nginx/sites-available/staged /etc/nginx/sites-enabled
```

Validate the config and reload nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

If all went well, your instance should now be accessible on the Internet.

===

# updating staged
Make sure to check these instructions each time you update staged, as they may change slightly.

It is best to do this at a time of low-activity, or use a mechanism to route new requests to a different server while updating.
Such mechanisms are outside the scope of these instructions.

## update the daemon

### login as stagedupd
Login as stagedupd and activate the venv:
```bash
sudo -u stagedupd bash
cd ~
source ~/venv/bin/activate
```

### download
Find the latest release tarball [on the releases page](https://github.com/web-presentation-clicker/staged/releases).
Make sure to read the release notes to see if there are any extra steps that must be performed.
Download and extract it:
```bash
mkdir -p ~/downloaded
rm -rf ~/downloaded/*
cd ~/downloaded

curl https://github.com/web-presentation-clicker/staged/releases/download/<VERSION CODE>/staged.tar.gz -Lo staged.tar.gz

tar -xvf staged.tar.gz
rm staged.tar.gz

cd ~
```

Swap out the installed server directory:
```bash
rm -rf ~/app-old
mv ~/app ~/app-old
cp -r ~/downloaded/staged/server ~/app
```

### update python packages
Update the requirements from `requirements.txt`:
```bash
pip install -Ur ~/app/requirements.txt
```

### log out
Press ctrl+D or type `exit` to go back to your normal user.


## update static pages
Copy the static pages used for the clicker into place.

```bash
sudo rm -rf /var/www/staged-old
sudo mv /var/www/staged /var/www/staged-old
sudo cp -r /opt/staged/downloaded/staged/static /var/www/staged
```


## restart the daemon
Reminder: this will terminate all active presentation sessions, forcing users to re-pair their devices.
```bash
sudo systemctl restart staged-sessionserver.service
sudo systemctl restart staged.service
```

These commands may take a while. You can monitor progress in another shell:
```bash
sudo journalctl -efu staged-sessionserver.service --output=cat
sudo journalctl -efu staged.service --output=cat
```

### check status and monitor logs
Make sure nothing is broken:
```bash
# check status
sudo systemctl status staged-sessionserver.service
sudo systemctl status staged.service

# monitor logs
sudo journalctl -efu staged-sessionserver.service --output=cat
sudo journalctl -efu staged.service --output=cat
```

### clean up
Once you are sure everything is working, you can (optionally) delete the downloaded/old files.

```bash
sudo rm -rf /opt/staged/downloaded /opt/staged/app-old /var/www/staged-old
```
