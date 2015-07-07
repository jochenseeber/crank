# Headless Ubuntu Installation

Crank is a tool to perform automated headless Ubuntu installations using only a SSH connection.

## Installation

To install crank, run the folloing command:

```bash
sudo gem install crank
```

Crank also requires [ngrok] to serve configuration files. Head to their web site to download and install it.

[ngrok]: https://ngrok.com/

## Introduction

Crank is designed to perform automated Ubuntu installations on remote servers (e.g. provided by your ISP). In order to run crank, you need to be able to SSH into the server, either by booting a rescue system or by using an existing preinstalled system.

Installations are performed by running the Ubuntu netboot installer using one of the following methods:

* `kexec`: Run the installer using [kexec]. Fast and simple.
* `qemu`: Run the installer using [QEMU]. Slower, but sometimes `kexec` is not available.
* `disk`: Installs a boot loader on the first hard disk and boot the installer from there. Use if all else fails.

The `qemu` and `disk` methods both write to the disk, so in order to work, the current system must not use the hard drives. Usually this is achieved by booting the server's rescue system using your ISP's management interface.

[kexec]: http://manpages.ubuntu.com/manpages/yakkety/man8/kexec.8.html
[QEMU]: http://www.qemu-project.org/

## Examples

Install Ubuntu Xenial using the `kexec` method:

    crank install --mode kexec --ssh-password xxx server.company.com

Install Ubuntu Xenial using the `qemu` method:

    crank install --mode qemu --ssh-password xxx server.company.com

Install Ubuntu Xenial using the `disk` method:

    crank install --mode disk --ssh-password xxx server.company.com

## Advanced configuration

See `crank install --help` for a list of options.

## Limitations

* Crank currently requires the base system to be Ubuntu or Debian
* It's only tested with Ubuntu Xenial
