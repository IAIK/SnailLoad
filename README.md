# SnailLoad Demo Webserver

This repository contains the source code for the [SnailLoad](https://www.snailload.com) example webserver, as showcased on http://demo.snailload.com

The webserver demonstrates that TCP round trip times carry side-channel information about the current network activity on a victim's internet connection.
The code shows how a Linux server process obtains network latency traces from a TCP connection initiated by the victim.
The demo webserver slowly generates a BMP file from the measured latencies on the fly and progressively sends it to the victim.
This demonstrates the most central claim of the SnailLoad paper: The network latency side channel can be observed from arbitrary TCP connections.

# Compile + Install

1. Clone the repo: `git clone https://github.com/IAIK/SnailLoad.git`
2. Change into the `SnailLoad/demo_server` directory: `cd SnailLoad/demo_server`.
3. Compile the server binary: `make`
4. Copy the `demo_server` binary and `index_html` to your virtual or dedicated server.
5. Log in to your server via SSH.
6. If the server binary should use a TCP port below 1024, adjust the capabilities: `sudo setcap cap_net_bind_service+ep demo_server`
7. Start the server binary on the designated TCP port: `./demo_server -p $PORT`, with `$PORT` being the port number.
