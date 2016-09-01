.. Security Supervision documentation master file, created by
   sphinx-quickstart on Sun May 15 19:54:45 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Security Supervision
====================

Welcome to security supervision system.

Click `here`_ to access it.

.. _here: https://secsup.ddns.net/app/kibana

Description
===========

The system offers a real-time supervision of attacks on a private server. Two dashboards are available:

 * the first one shows port-scan attacks on the system (TCP and UDP scan)
 * the second one shows authenticated connections and failed authentication attempts to these two dashboards

All attacks are geolocated and can be viewed in real-time.

It's based on ELK technology (Elasticsearch, Logstash and Kibana) which is the standard of open-sourced SIEM (Security Informations and Events Management).

`Enjoy`_ !

.. _Enjoy: https://secsup.ddns.net/app/kibana

Git project
===========

Prerequisites
=============

First:
Go to ovh/amazon account on a web browser
Install debian 8 on a VM
Ensure there is a public dns associated to VM (example: secsup.ovh)

On target VM:
Connect it as root, change password and create a new user: adduser adminfra
Add user in sudo group: usermod -a -G sudo adminfra
Disable ssh as root: vim /etc/ssh/sshd_config and replace "PermitRootLogin yes" by "PermitRootLogin no"
Change ssh port: vim /etc/ssh/sshd_config and replace "Port 22" by "Port 40000"
Restart ssh service: service ssh restart

Next let's create certificates, using let's envrypt initiative.
Connect to target VM as adminfra.
Install jessie-backports: add this line in /etc/apt/sources.list : deb http://ftp.debian.org/debian/ jessie-backports main contrib non-free
sudo apt update
sudo apt-get install certbot -t jessie-backports
sudo certbot certonly
Chose : 2 - Automatically use a temporary webserver (standalone)
Enter : adminfra@secsup.ovh
Chose : Agree
Enter : secsup.ovh
Certificates have been saved at /etc/letsencrypt/live/secsup.ovh/fullchain.pem
Copy certificates on adminfra home directory : sudo cp -r /etc/letsencrypt/archive/secsup.ovh ~
Create www-data user: sudo adduser www-data
Change certificates owner : sudo chown -R adm-infra:adm-infra ~/secsup.ovh/
Change rights : sudo chmod 600 ~/secsup.ovh/privkey1.pem
Get back all certificates directory on deploy VM: sudo scp -r /etc/letsencrypt/archive/secsup.ovh <deploy user>@<deploy ip>:~

On deploy VM:
Create ssh key: ssh-keygen
Copy it on target VM: ssh-copy-id adminfra@secsup.ovh -p 40000
Install ansible, python-yaml, python-paramiko

Automatic deployment
====================

Configure inventory : vim supervision.inv
Launch Ansible : ansible-playbook -i supervision.inv -u adminfra supervision.yml -K -k

Perspectives
============
