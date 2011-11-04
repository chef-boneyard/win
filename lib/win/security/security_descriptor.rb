require 'win/security'
require 'win/security/acl'
require 'win/security/sid'

module Win
  module Security
    class SecurityDescriptor
      def initialize(pointer)
        @pointer = pointer
      end

      attr_reader :pointer

      def make_absolute(&block)
        Win::Security.make_absolute_sd(self, &block)
      end

      def owner
        result, defaulted = Win::Security.get_security_descriptor_owner(self)
        result
      end

      def group
        result, defaulted = Win::Security.get_security_descriptor_group(self)
        result
      end

      def control
        result, version = Win::Security.get_security_descriptor_control(self)
        result
      end

      def dacl
        return nil if (control & SE_DACL_PRESENT) == 0
        present, acl, defaulted = Win::Security.get_security_descriptor_dacl(self)
        acl
      end

      def dacl=(acl)
        Win::Security.set_security_descriptor_dacl(self, acl)
      end

      def sacl
        raise "SACL not present" if (control & SE_SACL_PRESENT) == 0
        present, acl, defaulted = Win::Security.get_security_descriptor_sacl(self)
        acl
      end
    end
  end
end
