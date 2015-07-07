require "commander"
require "crank/command/install"
require "crank/version"
require "facets/string/snakecase"

module Crank
  # Crank application class
  class Application
    include Commander::Methods

    # Run the command
    def initialize
      program :name, "crank"
      program :version, Crank::VERSION
      program :description, "Automated Ubuntu server setup"

      register_command(type: Command::Install)
    end

    def register_command(type:)
      command(type.name.split("::").last.snakecase.to_sym) do |c|
        c.action do |args, options|
          cmd = type.new(args: args, options: options)
          cmd.run
        end

        type.register(command: c)
      end
    end
  end
end
