# SnailLoad Demo Webserver

This repository contains the source code for the SnailLoad example webserver, as showcased on https://demo.snailload.com

# Compile + Install

1. Clone the repo: `git clone https://github.com/IAIK/SnailLoad.git`
2. Change into the `SnailLoad/demo_server` directory: `cd SnailLoad/demo_server`.
3. Compile the server binary: `make`
4. Copy the `demo_server` binary and `index_html` to your virtual or dedicated server.
5. Log in to your server via SSH.
6. If the server binary should use a TCP port below 1024, adjust the capabilities: `sudo setcap cap_net_bind_service+ep demo_server`
7. Start the server binary on the designated TCP port: `./demo_server -p $PORT`, with `$PORT` being the port number.
