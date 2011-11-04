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
        result = FFI::Buffer.new :pointer
        owner_defaulted = FFI::Buffer.new :long
        unless Win::Security.GetSecurityDescriptorOwner(pointer, result, owner_defaulted)
          Win::Security.raise_last_error
        end
        SID.new(result.read_pointer)
      end

      def group
        result = FFI::Buffer.new :pointer
        group_defaulted = FFI::MemoryPointer.new :long
        unless Win::Security.GetSecurityDescriptorGroup(pointer, result, group_defaulted)
          Win::Security.raise_last_error
        end
        SID.new(result.read_pointer)
      end

      def control
        result = FFI::Buffer.new :ushort
        version = FFI::Buffer.new :uint32
        # TODO we're getting an error from this, but we're also getting reasonable values.  Investigate and restore error handling.
        Win::Security.GetSecurityDescriptorControl(pointer, result, version)
        result.read_ushort
      end

      def dacl
        raise "DACL not present" if (control & SE_DACL_PRESENT) == 0
        present = FFI::Buffer.new :bool
        defaulted = FFI::Buffer.new :bool
        acl = FFI::Buffer.new :pointer
        unless Win::Security.GetSecurityDescriptorDacl(pointer, present, acl, defaulted)
          Win::Security.raise_last_error
        end
        ACL.new(acl.read_pointer)
      end
    end

    def sacl
      raise "SACL not present" if (control & SE_SACL_PRESENT) == 0
      present = FFI::Buffer.new :bool
      defaulted = FFI::Buffer.new :bool
      acl = FFI::Buffer.new :pointer
      unless Win::Security.GetSecurityDescriptorSacl(pointer, present, acl, defaulted)
        Win::Security.raise_last_error
      end
      ACL.new(acl.read_pointer)
    end
  end
end
