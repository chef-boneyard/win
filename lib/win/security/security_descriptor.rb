require 'win/security'
require 'win/security/acl'
require 'win/security/sid'

module Win
  module Security
    class SecurityDescriptor
      def initialize(pointer)
        # TODO I think we're leaking this
        @pointer = pointer
      end

      attr_reader :pointer

      def owner
        result, defaulted = Win::Security.get_security_descriptor_owner(pointer)
        result
      end

      def group
        result, defaulted = Win::Security.get_security_descriptor_group(pointer)
        result
      end

      def control
        result, version = Win::Security.get_security_descriptor_control(pointer)
        result
      end

      def dacl
        raise "DACL not present" if (control & SE_DACL_PRESENT) == 0
        present, acl, defaulted = Win::Security.get_security_descriptor_dacl(pointer)
        acl
      end

      def sacl
        raise "SACL not present" if (control & SE_SACL_PRESENT) == 0
        present, acl, defaulted = Win::Security.get_security_descriptor_sacl(pointer)
        acl
      end
    end
  end
end
