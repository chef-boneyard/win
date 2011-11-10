require 'win/security'
require 'win/security/acl'
require 'win/security/sid'

module Win
  module Security
    class SecurableObject
      def initialize(path, type = :SE_FILE_OBJECT)
        @path = path
        @type = type
      end

      attr_reader :pointer

      def dacl
        Win::Security::get_named_security_info(@path, @type, DACL_SECURITY_INFORMATION).dacl
      end

      def dacl=(val)
        Win::Security::set_named_security_info(@path, @type, :dacl => val)
      end

      def dacl_inherits?
        Win::Security::get_named_security_info(@path, @type, DACL_SECURITY_INFORMATION).dacl_inherits?
      end

      # You don't set dacl_inherits without also setting dacl because Windows gets angry and denies you access
      def set_dacl(dacl, dacl_inherits)
        Win::Security::set_named_security_info(@path, @type, :dacl => dacl, :dacl_inherits => dacl_inherits)
      end

      def group
        Win::Security::get_named_security_info(@path, @type, GROUP_SECURITY_INFORMATION).group
      end

      def group=(val)
        Win::Security::set_named_security_info(@path, @type, :group => val)
      end

      def owner
        Win::Security::get_named_security_info(@path, @type, OWNER_SECURITY_INFORMATION).owner
      end

      def owner=(val)
        Win::Security::set_named_security_info(@path, @type, :owner => val)
      end

      def sacl
        Win::Security::get_named_security_info(@path, @type, SACL_SECURITY_INFORMATION).sacl
      end

      def sacl=(val)
        Win::Security::set_named_security_info(@path, @type, :sacl => val)
      end

      def sacl_inherits?
        Win::Security::get_named_security_info(@path, @type, SACL_SECURITY_INFORMATION).sacl_inherits?
      end

      def set_sacl(sacl, sacl_inherits)
        Win::Security::set_named_security_info(@path, @type, :sacl => sacl, :sacl_inherits => sacl_inherits)
      end
    end
  end
end
