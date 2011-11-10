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

      def absolute?
        !self_relative?
      end

      def control
        control, version = Win::Security.get_security_descriptor_control(self)
        control
      end

      def dacl
        raise "DACL not present" if !dacl_present?
        present, acl, defaulted = Win::Security.get_security_descriptor_dacl(self)
        acl
      end

      def dacl_inherits?
        (control & SE_DACL_PROTECTED) == 0
      end

      def dacl_present?
        (control & SE_DACL_PRESENT) != 0
      end

      def group
        result, defaulted = Win::Security.get_security_descriptor_group(self)
        result
      end

      def owner
        result, defaulted = Win::Security.get_security_descriptor_owner(self)
        result
      end

      def sacl
        raise "SACL not present" if !sacl_present?
        present, acl, defaulted = Win::Security.get_security_descriptor_sacl(self)
        acl
      end

      def sacl_inherits?
        (control & SE_SACL_PROTECTED) == 0
      end

      def sacl_present?
        (control & SE_SACL_PRESENT) != 0
      end

      def self_relative?
        (control & SE_SELF_RELATIVE) != 0
      end

      def valid?
        Win::Security.is_valid_security_descriptor(self)
      end
    end
  end
end
