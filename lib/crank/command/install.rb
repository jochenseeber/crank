require "andand"
require "base32"
require "erubis"
require "facets/string/random"
require "facets/string/unindent"
require "ipaddress"
require "json"
require "jsonpath"
require "ostruct"
require "rest-client"
require "rye"
require "securerandom"
require "socket"
require "timeout"
require "webrick"
require "set"

module Crank
  module Command
    class Install
      OPTION_PROPERTIES = [
        :config,
        :dhcp,
        :domainname,
        :hostname,
        :password,
        :sudo,
        :username,
      ]

      attr_reader :config
      attr_reader :dhcp
      attr_reader :directories
      attr_reader :domainname
      attr_reader :hostname
      attr_reader :ipaddress
      attr_reader :mode
      attr_reader :password
      attr_reader :server
      attr_reader :ssh_password
      attr_reader :ssh_port
      attr_reader :ssh_user
      attr_reader :ssh_user
      attr_reader :sudo
      attr_reader :username
      attr_reader :version

      def initialize(args:, options:)
        @directories =  Array(options.directory) + [File.expand_path(File.join(File.dirname(__FILE__), "../../../files"))]
        @config = options.config || "default"
        @dhcp = options.dhcp.nil? ? true : options.dhcp
        @domainname = args.first[/^[^.]+\.(.+)/, 1]
        @hostname = args.first[/^[^.]+/]
        @ipaddress = options.ipaddress
        @mode = (options.mode || :kexec).to_sym
        @password = String.random(16)
        @reboot = options.reboot || false
        @server = args.first
        @ssh_password = options.ssh_password
        @ssh_port = options.ssh_port || 22
        @ssh_user = options.ssh_user || "root"
        @sudo = options.sudo.nil? ? (@ssh_user != "root") : options.sudo
        @username = "root"
        @version = options.version || "xenial"
      end

      def run
        ssh_options = {
          safe: false,
          user: @ssh_user,
          password: @ssh_password,
          port: @ssh_port,
          password_prompt: false,
          sudo: @sudo
        }

        ssh = Rye::Box.new(@server, ssh_options)

        prepare_server(ssh: ssh)

        options = get_options
        get_server_info(ssh: ssh).each_pair do |k, v|
          options[k] = v
        end

        ssh_key_file = File.expand_path("~/.ssh/id_rsa.pub")

        if File.exist?(ssh_key_file)
          options.ssh_key = IO.read(ssh_key_file).chomp
        end

        start_ngrok

        options.base_url = start_tunnel

        puts "Options"
        puts "======="
        options.marshal_dump.each do |k, v|
          puts "#{k}: #{v}"
        end

        start_http_server(options: options)

        case mode
        when :disk
          disk_install(ssh: ssh, options: options)
        when :kexec
          kexec_install(ssh: ssh, options: options)
        when :qemu
          qemu_install(ssh: ssh, options: options)
        else
          raise "Illegal mode #{mode}"
        end

        sleep
      end

      def self.register(command:)
        command.description = "Install a new server"
        command.option "--[no-]dhcp", "Use DHCP to configure network"
        command.option "--ssh-password STRING", String, "SSH password"
        command.option "--ssh-port STRING", String, "SSH port"
        command.option "--ssh-user STRING", String, "SSH user"
        command.option "-a", "--ipaddress STRING", String, "IP and netmask address of the server"
        command.option "-c", "--config STRING", String, "Name of configuration file"
        command.option "-d", "--directory STRING", Array, "Additional directory to serve configuration files from"
        command.option "-m", "--mode String", "Installation mode (kexec, disk or qemu)"
        command.option "-p", "--password STRING", String, "Password for the user created by the installer"
        command.option "-r", "--[no-]reboot", "Automatically reboot system during installation"
        command.option "-s", "--sudo", "Use sudo to execute commands"
        command.option "-v", "--version STRING", String, "Ubuntu version"
      end

      protected

      def start_ngrok
        if is_port_open?(address: "127.0.0.1", port: 4040)
          puts "==> Using running ngrok"
        else
          puts "==> Starting ngrok"
          p = fork do
            Process.setsid
            exec "ngrok start --none --log false"
          end

          Timeout.timeout(10) do
            while not is_port_open?(address: "127.0.0.1", port: 4040)
              sleep 1
            end
          end
        end
      end

      def start_tunnel
        ngrok_client = RestClient::Resource.new "http://127.0.0.1:4040", headers: { content_type: :json, accept: :json }
        tunnel_url = nil
        response = ngrok_client["/api/tunnels"].get
        json = JSON.parse response.to_str
        json["tunnels"].each do |tunnel|
          if tunnel["proto"] == "http" and tunnel["config"]["addr"] == "localhost:8000"
            tunnel_url = tunnel["public_url"]
            puts "==> Using existing tunnel #{tunnel['name']}"
            break
          end
        end

        if tunnel_url.nil? then
          tunnel_name = Base32.encode([SecureRandom.uuid.gsub("-", "")].pack("H*")).gsub(/=+$/,"")

          params = {
            addr: 8000,
            proto: "http",
            name: tunnel_name,
            bind_tls: false
          }

          puts "==> Creating tunnel #{tunnel_name}"
          response = ngrok_client["/api/tunnels"].post params.to_json
          json = JSON.parse(response.to_str)
          tunnel_url = json["public_url"]
        end

        tunnel_url
      end

      def start_http_server(options:)
        server = WEBrick::HTTPServer.new(Port: 8000, DocumentRoot: directories.first)

        server.mount_proc "/" do |request, response|
          file_name = directories.map {|d| File.join(d, "#{request.path}.eruby")}.find{|f| File.exist?(f)}

          if file_name.nil?
            raise WEBrick::HTTPStatus::NotFound, "'#{request.path}' not found."
          end

          template = Erubis::Eruby.new(File.read(file_name))
          response.body = template.result(options.marshal_dump)
        end

        @server_pid = fork do
          trap("INT") do
            server.shutdown
          end

          server.start
        end

        at_exit do
          Process.kill("INT", @server_pid)
        end
      end

      def get_options
        options = OpenStruct.new

        OPTION_PROPERTIES.each do |p|
          options[p] = public_send(p)
        end

        options
      end

      def get_server_info(ssh:)
        puts "==> Checking hardware"
        info = JSON.parse(ssh.execute("lshw -json").to_s)

        network = JsonPath.new("$..children[?(@['class'] == 'network' and @['configuration']['ip'])]").on(info).first
        disks = JsonPath.new("$..children[?(@['class'] == 'disk')]").on(info)

        options = OpenStruct.new
        options.disk_count = disks.size
        options.ipaddress = @ipaddress.andand{|a| IPAddress.parse(a)}

        if options.ipaddress.nil?
          puts "==> Checking network"
          info = ssh.execute("ip addr show up").to_s
          interface = nil

          info.each_line do |line|
            if line =~ /^[0-9]+:\s+(\w+):/
              if $1 != "lo"
                interface = $1
              else
                interface = nil
              end
            elsif interface != nil
              if line =~ /\s+inet\s+([0-9.\/]+)/
                options.ipaddress = IPAddress.parse($1)
                break
              end
            end
          end
        end

        puts "==> Checking routing"
        info = ssh.execute("ip route show").to_s
        info.each_line do |line|
          if line =~ /^default via ([0-9.]+)/
            options.gateway = IPAddress.parse($1)
          end
        end

        info = ssh.execute("cat /etc/resolv.conf").to_s
        info.each_line do |line|
          if line =~ /^nameserver ([0-9.]+)/
            options.nameserver = IPAddress.parse($1)
            break
          end
        end

        options
      end

      def prepare_server(ssh:)
        puts "==> Installing software"
        ssh.setenv("DEBIAN_FRONTEND", "noninteractive")
        ssh.execute("apt-get -yqq update")

        packages = [
          "curl",
          "lshw",
        ]

        case mode
        when :disk
          packages = packages + ["parted", "extlinux"]
        when :kexec
          packages = packages + ["kexec-tools"]
        when :qemu
          packages = packages + ["qemu"]
        end

        packages.each do |p|
          puts "==> Installing #{p}"
          ssh.execute("apt-get install -yqq #{p}")
        end

        puts "==> Downloading kernel and initrd"
        ssh.execute("curl -L -O 'http://archive.ubuntu.com/ubuntu/dists/#{version}/main/installer-amd64/current/images/netboot/ubuntu-installer/amd64/linux'")
        ssh.execute("curl -L -O 'http://archive.ubuntu.com/ubuntu/dists/#{version}/main/installer-amd64/current/images/netboot/ubuntu-installer/amd64/initrd.gz'")
      end

      def disk_install(ssh:, options:)
        puts "==> Delete RAID devices"
        raid_devices = Set.new
        disk_devices = Set.new

        output = ssh.execute("lsblk -l -i -n -p -o NAME,TYPE")
        output.stdout.each do |line|
          if line =~ %r{^([a-z0-9/]+)\s+raid[0-9]+$}
            raid_devices << $1
          end
          if line =~ %r{^([a-z0-9/]+)\s+part$}
          end
        end

        raid_devices.each do |d|
          puts "==> Deleting raid #{d}"
          ssh.execute("mdadm --stop #{d}")
        end

        puts "==> Deleting raid #{$1}"
        disk_devices.each do |d|
          puts "==> Zeroing superblock on #{d}"
          ssh.execute("mdadm --zero-superblock #{d}")
        end

        puts "==> Partitioning disk"
        ssh.execute("umount /mnt/boot || true")
        ssh.execute("parted -s -a optimal /dev/sda mklabel msdos")
        ssh.execute("parted -s -a optimal /dev/sda mkpart primary ext4 0% 1024")
        ssh.execute("parted -s -a optimal /dev/sda set 1 boot on")

        # GPT (not working)
        # ssh.execute("parted -s -a optimal /dev/sda mklabel gpt")
        # ssh.execute("parted -s -a optimal /dev/sda mkpart primary 2048s 4095s")
        # ssh.execute("parted -s -a optimal /dev/sda mkpart primary ext4 4096s 1GiB")
        # ssh.execute("parted -s -a optimal /dev/sda set 1 bios_grub on")
        # ssh.execute("parted -s -a optimal /dev/sda set 2 legacy_boot on")

        ssh.execute("if [ -e /dev/sdb ]; then parted -s -a optimal /dev/sdb mklabel msdos; fi")

        puts "==> Creating file system"
        ssh.execute("mkfs.ext4 /dev/sda1")

        puts "==> Mounting file system"
        ssh.execute("mkdir -p /mnt/boot || true")
        ssh.execute("mount /dev/sda1 /mnt/boot")

        puts "==> Copying kernel and initrd"
        ssh.execute("cp linux /mnt/boot")
        ssh.execute("cp initrd.gz /mnt/boot")

        puts "==> Installing extlinux"
        config = <<-EOS.unindent
        DEFAULT installer
        TIMEOUT 1

        LABEL installer
        KERNEL linux
        INITRD initrd.gz
        APPEND #{get_kernel_options(options: options)}
        EOS

        ssh.file_upload(StringIO.new(config), "/mnt/boot/extlinux.conf")
        ssh.execute("cat /usr/lib/EXTLINUX/mbr.bin >/dev/sda")
        ssh.execute("extlinux --install /mnt/boot")

        if options.reboot
          ssh.execute("reboot")
        else
          puts "==> Execute 'reboot' on the server to reboot and start installation"
        end
      end

      def qemu_install(ssh:, options:)
        command = "qemu-system-x86_64 -m 2048 -nographic -no-reboot"

        (0..options.disk_count - 1).each do |i|
          ch = ("a".ord + i).chr
          command += " -hd#{ch} /dev/sd#{ch}"
        end

        command += " -kernel linux -initrd initrd.gz -append '#{get_kernel_options(options: options)}'"

        if options.reboot
          ssh.execute(command)
        else
          puts "==> Execute '#{command}' on the server run QEMU and start installation"
        end
      end

      def kexec_install(ssh:, options:)
        puts "==> Configuring kexec"
        ssh.execute("kexec -l linux --initrd initrd.gz --append '#{get_kernel_options(options: options)}'")

        if options.reboot
          ssh.execute("kexec -e")
        else
          puts "==> Execute 'kexec -e' on the server to boot into installer and start installation"
        end
      end

      def get_kernel_options(options:)
        kernel_options = {
          "auto" => "true",
          "priority" => "critical",
          "language" => "en",
          "country" => "DE",
          "locale" => "en_US.UTF-8",
          "keymap" => "skip-config",
          "url" => "#{options.base_url}/#{config}.preseed",
          "console" => "ttyS0,57600",
          "DEBCONF_DEBUG" => "5",
          "netcfg/choose_interface" => "auto",
          "hostname" => options.hostname,
        }

        if not dhcp
          static_options = {
            "netcfg/confirm_static" => true,
            "netcfg/disable_autoconfig" => true,
            "netcfg/disable_dhcp" => true,
            "netcfg/get_gateway" => options.gateway.to_s,
            "netcfg/get_ipaddress" => options.ipaddress.to_s,
            "netcfg/get_nameservers" => options.nameserver.to_s,
            "netcfg/get_netmask" => options.ipaddress.netmask,
            "domain" => options.domainname,
          }

          kernel_options.merge!(static_options)
        end

        kernel_options.map {|k, v| "#{k}=#{v.andand.to_s}"}.join(" ")
      end

      def is_port_open?(address:, port:)
        socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
        socket_address = Socket.sockaddr_in(port, address)
        socket_open = false

        begin
          socket.connect_nonblock(socket_address)
        rescue Errno::EINPROGRESS
          if IO.select(nil, [socket], nil, 1)
            begin
              socket.connect_nonblock(socket_address)
            rescue Errno::EISCONN
              socket_open = true
            rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
              socket_open = false
            end
          end
        end

        socket_open
      end
    end
  end
end
