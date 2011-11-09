require 'win/security'
require 'win/security/acl'
require 'win/security/sid'

module Win
  module Security
    class SecurityDescriptor
      def initialize(pointer, owner = nil, group = nil, dacl = nil, sacl = nil)
        @pointer = pointer
        @owner = owner
        @group = group
        @dacl = dacl
        @sacl = sacl
      end

      attr_reader :pointer

      def absolute?
        !self_relative?
      end

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
        control, version = Win::Security.get_security_descriptor_control(self)
        control
      end

      def dacl
        raise "DACL not present" if !dacl_present?
        return @dacl if @dacl != nil
        present, acl, defaulted = Win::Security.get_security_descriptor_dacl(self)
        acl
      end

      def dacl=(acl)
        Win::Security.set_security_descriptor_dacl(self, acl)
        @dacl = acl
      end

      def dacl_present?
        (control & SE_DACL_PRESENT) != 0
      end

      def group
        return @group if @group != nil
        result, defaulted = Win::Security.get_security_descriptor_group(self)
        result
      end

      def group=(sid)
        Win::Security.set_security_descriptor_group(self, sid)
        @group = sid
      end

      # Useful when you need a copy of a system SD that you can modify
      def make_absolute
        Win::Security.make_absolute_sd(self)
      end

      def owner
        return @owner if @owner != nil
        result, defaulted = Win::Security.get_security_descriptor_owner(self)
        result
      end

      def owner=(sid)
        Win::Security.set_security_descriptor_owner(self, sid)
        @owner = sid
      end

      def sacl
        raise "SACL not present" if !sacl_present?
        return @sacl if @sacl != nil
        present, acl, defaulted = Win::Security.get_security_descriptor_sacl(self)
        acl
      end

      def sacl=(acl)
        Win::Security.set_security_descriptor_sacl(self, acl)
        @sacl = acl
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
