# Installation

First compile cbridge.

```
make -C src
```

Optionally compile some tools.
```
make -C tools
```

In a directory of your choice, install
- a cbridge.conf file (see [EXAMPLES](EXAMPLES.md) for examples),
- the support/ca-chain.cert.pem file, and your own certificates and keys, and
- the other cbridge [support files](../support). You can use the ```support``` directory itself, of course.

You probably need to edit the other [support scripts](../support) to reflect what your directory of choice is. You should read these files and try to understand them.

Copy the cbridge binary to the directory of choice. Optionally install the compiled tools/clients in your PATH.

Start cbridge, e.g. using one of the following ways:
- manually: ```sudo cbridge```
- systemd (Linux):
  1. copy the cbridge.service and cbridge-crl-update.{timer,service} files to /etc/systemd/system,
  2. ```sudo systemd daemon-reload```
  3. ```sudo systemd enable cbridge```
  4. ```sudo systemd enable --now cbridge-crl-update.timer```
  5. ```sudo systemd start cbridge```
- launchd (macOS):
  1. copy the cbridge plist file to ~/Library/LaunchAgents/net.chaosnet.cbridge.plist
  2. ```launchctl load -w ~/Library/LaunchAgents/net.chaosnet.cbridge.plist```

Try it, e.g. using
- ```hostat 3040```
- ```hostat 3162```
- ```python3 bhostat.py -1```

## Problems?

If you run into problems, please make sure to read the documentation and any output from cbridge. Try running cbridge with the "-v", "-d", and/or "-t" flags to get more detailed output, and look into the "trace" and "debug" options for the [configuration](CONFIGURATION.md) file. If you can't make it work, contact Björn, providing relevant config files and log output.
