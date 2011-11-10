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

      def security_descriptor(include_sacl = false)
        security_information = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        security_information |= SACL_SECURITY_INFORMATION if include_sacl
        Win::Security::get_named_security_info(@path, @type, security_information)
      end

      def dacl=(val)
        Win::Security::set_named_security_info(@path, @type, :dacl => val)
      end

      # You don't set dacl_inherits without also setting dacl because Windows gets angry and denies you access
      def set_dacl(dacl, dacl_inherits)
        Win::Security::set_named_security_info(@path, @type, :dacl => dacl, :dacl_inherits => dacl_inherits)
      end

      def group=(val)
        Win::Security::set_named_security_info(@path, @type, :group => val)
      end

      def owner=(val)
        Win::Security::set_named_security_info(@path, @type, :owner => val)
      end

      def sacl=(val)
        Win::Security::set_named_security_info(@path, @type, :sacl => val)
      end

      def set_sacl(sacl, sacl_inherits)
        Win::Security::set_named_security_info(@path, @type, :sacl => sacl, :sacl_inherits => sacl_inherits)
      end
    end
  end
end
