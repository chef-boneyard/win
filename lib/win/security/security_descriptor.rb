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

      def apply_to(path, type = :SE_FILE_OBJECT, security_information = nil)
        Win::Security.set_named_security_info(path,
          owner,
          group,
          dacl_present? ? dacl : nil,
          sacl_present? ? sacl : nil,
          type,
          security_information
        )
      end

      def control
        result, version = Win::Security.get_security_descriptor_control(self)
        result
      end

      def dacl
        raise "DACL not present" if !dacl_present?
        present, acl, defaulted = Win::Security.get_security_descriptor_dacl(self)
        acl
      end

      def dacl=(acl)
        Win::Security.set_security_descriptor_dacl(self, acl)
      end

      def dacl_present?
        (control & SE_DACL_PRESENT) != 0
      end

      def group
        result, defaulted = Win::Security.get_security_descriptor_group(self)
        result
      end

      def group=(sid)
        Win::Security.set_security_descriptor_group(self, sid)
      end

      # Useful when you need a copy of a system SD that you can modify
      def make_absolute(&block)
        Win::Security.make_absolute_sd(self, &block)
      end

      def owner
        result, defaulted = Win::Security.get_security_descriptor_owner(self)
        result
      end

      def owner=(sid)
        Win::Security.set_security_descriptor_owner(self, sid)
      end

      def sacl
        raise "SACL not present" if !sacl_present?
        present, acl, defaulted = Win::Security.get_security_descriptor_sacl(self)
        acl
      end

      def sacl=(acl)
        Win::Security.set_security_descriptor_sacl(self, acl)
      end

      def sacl_present?
        (control & SE_SACL_PRESENT) != 0
      end

      def valid?
        Win::Security.is_valid_security_descriptor(self)
      end
    end
  end
end
