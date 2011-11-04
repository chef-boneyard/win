require 'rubygems'
require 'iconv'
require 'win/library'
require 'win/error'
require 'win/memory'
require 'win/security/security_descriptor'

module Win
  module Security
    extend Win::Library

    # SE_OBJECT_TYPE Enumeration
    SE_OBJECT_TYPE = enum :SE_OBJECT_TYPE, [
         :SE_UNKNOWN_OBJECT_TYPE,
         :SE_FILE_OBJECT,
         :SE_SERVICE,
         :SE_PRINTER,
         :SE_REGISTRY_KEY,
         :SE_LMSHARE,
         :SE_KERNEL_OBJECT,
         :SE_WINDOW_OBJECT,
         :SE_DS_OBJECT,
         :SE_DS_OBJECT_ALL,
         :SE_PROVIDER_DEFINED_OBJECT,
         :SE_WMIGUID_OBJECT,
         :SE_REGISTRY_WOW64_32KEY
    ]

    SID_NAME_USE = enum :SID_NAME_USE, [
         :SidTypeUser, 1,
         :SidTypeGroup,
         :SidTypeDomain,
         :SidTypeAlias,
         :SidTypeWellKnownGroup,
         :SidTypeDeletedAccount,
         :SidTypeInvalid,
         :SidTypeUnknown,
         :SidTypeComputer,
         :SidTypeLabel 
    ]

    # ACE_HEADER AceType
    ACCESS_MIN_MS_ACE_TYPE                   = 0x0
    ACCESS_ALLOWED_ACE_TYPE                  = 0x0
    ACCESS_DENIED_ACE_TYPE                   = 0x1
    SYSTEM_AUDIT_ACE_TYPE                    = 0x2
    SYSTEM_ALARM_ACE_TYPE                    = 0x3
    ACCESS_MAX_MS_V2_ACE_TYPE                = 0x3
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE         = 0x4
    ACCESS_MAX_MS_V3_ACE_TYPE                = 0x4
    ACCESS_MIN_MS_OBJECT_ACE_TYPE            = 0x5
    ACCESS_ALLOWED_OBJECT_ACE_TYPE           = 0x5
    ACCESS_DENIED_OBJECT_ACE_TYPE            = 0x6
    SYSTEM_AUDIT_OBJECT_ACE_TYPE             = 0x7
    SYSTEM_ALARM_OBJECT_ACE_TYPE             = 0x8
    ACCESS_MAX_MS_OBJECT_ACE_TYPE            = 0x8
    ACCESS_MAX_MS_V4_ACE_TYPE                = 0x8
    ACCESS_MAX_MS_ACE_TYPE                   = 0x8
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE         = 0x9
    ACCESS_DENIED_CALLBACK_ACE_TYPE          = 0xA
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE  = 0xB
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE   = 0xC
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE           = 0xD
    SYSTEM_ALARM_CALLBACK_ACE_TYPE           = 0xE
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE    = 0xF
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE    = 0x10
    SYSTEM_MANDATORY_LABEL_ACE_TYPE          = 0x11
    ACCESS_MAX_MS_V5_ACE_TYPE                = 0x11

    # ACE_HEADER AceFlags
    OBJECT_INHERIT_ACE                 = 0x1
    CONTAINER_INHERIT_ACE              = 0x2
    NO_PROPAGATE_INHERIT_ACE           = 0x4
    INHERIT_ONLY_ACE                   = 0x8
    INHERITED_ACE                      = 0x10
    VALID_INHERIT_FLAGS                = 0x1F
    SUCCESSFUL_ACCESS_ACE_FLAG         = 0x40
    FAILED_ACCESS_ACE_FLAG             = 0x80

    # SECURITY_INFORMATION flags (DWORD)
    OWNER_SECURITY_INFORMATION = 0x01
    GROUP_SECURITY_INFORMATION = 0x02
    DACL_SECURITY_INFORMATION = 0x04
    SACL_SECURITY_INFORMATION = 0x08
    LABEL_SECURITY_INFORMATION = 0x10
    UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
    UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
    PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000
    PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000

    # SECURITY_DESCRIPTOR_REVISION
    SECURITY_DESCRIPTOR_REVISION = 1

    # SECURITY_DESCRIPTOR_CONTROL
    SE_OWNER_DEFAULTED                = 0x0001
    SE_GROUP_DEFAULTED                = 0x0002
    SE_DACL_PRESENT                   = 0x0004
    SE_DACL_DEFAULTED                 = 0x0008
    SE_SACL_PRESENT                   = 0x0010
    SE_SACL_DEFAULTED                 = 0x0020
    SE_DACL_AUTO_INHERIT_REQ          = 0x0100
    SE_SACL_AUTO_INHERIT_REQ          = 0x0200
    SE_DACL_AUTO_INHERITED            = 0x0400
    SE_SACL_AUTO_INHERITED            = 0x0800
    SE_DACL_PROTECTED                 = 0x1000
    SE_SACL_PROTECTED                 = 0x2000
    SE_RM_CONTROL_VALID               = 0x4000
    SE_SELF_RELATIVE                  = 0x8000

    # ACCESS_RIGHTS_MASK
    # Generic Access Rights
    GENERIC_READ                      = 0x80000000
    GENERIC_WRITE                     = 0x40000000
    GENERIC_EXECUTE                   = 0x20000000
    GENERIC_ALL                       = 0x10000000
    # Standard Access Rights
    DELETE                            = 0x00010000
    READ_CONTROL                      = 0x00020000
    WRITE_DAC                         = 0x00040000
    WRITE_OWNER                       = 0x00080000
    SYNCHRONIZE                       = 0x00100000
    STANDARD_RIGHTS_REQUIRED          = 0x000F0000
    STANDARD_RIGHTS_READ              = READ_CONTROL
    STANDARD_RIGHTS_WRITE             = READ_CONTROL
    STANDARD_RIGHTS_EXECUTE           = READ_CONTROL
    STANDARD_RIGHTS_ALL               = 0x001F0000
    SPECIFIC_RIGHTS_ALL               = 0x0000FFFF
    # Access System Security Right
    ACCESS_SYSTEM_SECURITY            = 0x01000000
    # File/Directory Specific Rights
    FILE_READ_DATA             =  0x0001 
    FILE_LIST_DIRECTORY        =  0x0001 
    FILE_WRITE_DATA            =  0x0002 
    FILE_ADD_FILE              =  0x0002 
    FILE_APPEND_DATA           =  0x0004 
    FILE_ADD_SUBDIRECTORY      =  0x0004 
    FILE_CREATE_PIPE_INSTANCE  =  0x0004 
    FILE_READ_EA               =  0x0008 
    FILE_WRITE_EA              =  0x0010 
    FILE_EXECUTE               =  0x0020 
    FILE_TRAVERSE              =  0x0020 
    FILE_DELETE_CHILD          =  0x0040 
    FILE_READ_ATTRIBUTES       =  0x0080 
    FILE_WRITE_ATTRIBUTES      =  0x0100 
    FILE_ALL_ACCESS            = STANDARD_RIGHTS_REQUIRED |
                                 SYNCHRONIZE |
                                 0x1FF
    FILE_GENERIC_READ          = STANDARD_RIGHTS_READ |
                                 FILE_READ_DATA       |
                                 FILE_READ_ATTRIBUTES |
                                 FILE_READ_EA         |
                                 SYNCHRONIZE
    FILE_GENERIC_WRITE         = STANDARD_RIGHTS_WRITE    |
                                 FILE_WRITE_DATA          |
                                 FILE_WRITE_ATTRIBUTES    |
                                 FILE_WRITE_EA            |
                                 FILE_APPEND_DATA         |
                                 SYNCHRONIZE
    FILE_GENERIC_EXECUTE       = STANDARD_RIGHTS_EXECUTE  |
                                 FILE_READ_ATTRIBUTES     |
                                 FILE_EXECUTE             |
                                 SYNCHRONIZE

    # SECURITY_DESCRIPTOR is an opaque structure whose contents can vary.  Pass the
    # pointer around and free it with LocalFree.
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa379561(v=vs.85).aspx

    # SID is an opaque structure.  Pass the pointer around.

    # ACL type is a header with some information, followed by an array of ACEs
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa374931(v=VS.85).aspx
    class ACLStruct < FFI::Struct
      layout :AclRevision, :uchar,
             :Sbzl, :uchar,
             :AclSize, :ushort,
             :AceCount, :ushort,
             :Sbz2, :ushort
    end

    class ACE_HEADER < FFI::Struct
      layout :AceType, :uchar,
             :AceFlags, :uchar,
             :AceSize, :ushort
    end

    class ACE_WITH_MASK_AND_SID < FFI::Struct
      layout :AceType, :uchar,
             :AceFlags, :uchar,
             :AceSize, :ushort,
             :Mask, :uint32,
             :SidStart, :uint32

      # The AceTypes this structure supports
      def self.supports?(ace_type)
        [
            Win::Security::ACCESS_ALLOWED_ACE_TYPE,
            Win::Security::ACCESS_DENIED_ACE_TYPE,
            Win::Security::SYSTEM_AUDIT_ACE_TYPE,
            Win::Security::SYSTEM_ALARM_ACE_TYPE
        ].include?(ace_type)
      end
    end

    #
    # Windows functions
    #

    function :FreeSid, [ :pointer ], :pointer, :dll => "advapi32"
    def self.free_sid(sid)
      sid = sid.pointer if sid.respond_to?(:pointer)
      unless FreeSid(sid).null?
        Win::Error.raise_last_error
      end
    end

    function :GetAce, [ :pointer, :DWORD, :pointer ], :BOOL, :dll => "advapi32"
    def self.get_ace(acl, index)
      acl = acl.pointer if acl.respond_to?(:pointer)
      ace = FFI::Buffer.new :pointer
      unless GetAce(acl, index, ace)
        Win::Error.raise_last_error
      end
      ACE.new(ace.read_pointer)
    end

    function :GetNamedSecurityInfo,  [ :LPTSTR, :SE_OBJECT_TYPE, :DWORD, :pointer, :pointer, :pointer, :pointer, :pointer ], :DWORD, :dll => "advapi32"
    def self.get_named_security_info(path, type = :SE_FILE_OBJECT, info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &block)
      security_descriptor = FFI::MemoryPointer.new :pointer
      hr = GetNamedSecurityInfo(path, type, info, nil, nil, nil, nil, security_descriptor)
      if hr != Win::Error::S_OK
        Win::Error.raise_error(hr)
      end

      result = SecurityDescriptor.new(security_descriptor.read_pointer)
      if block != nil
        yield result
        Win::Memory.local_free(result.pointer)
      else
        result
      end
    end

    function :GetSecurityDescriptorControl, [ :pointer, :PWORD, :LPDWORD], :BOOL, :dll => "advapi32"
    def self.get_security_descriptor_control(security_descriptor)
      security_descriptor = security_descriptor.pointer if security_descriptor.respond_to?(:pointer)
      result = FFI::Buffer.new :ushort
      version = FFI::Buffer.new :uint32
      unless GetSecurityDescriptorControl(security_descriptor, result, version)
        Win::Error.raise_last_error
      end
      [ result.read_ushort, version.read_uint32 ]
    end

    function :GetSecurityDescriptorDacl, [ :pointer, :LPBOOL, :pointer, :LPBOOL ], :BOOL, :dll => "advapi32"
    def self.get_security_descriptor_dacl(security_descriptor)
      security_descriptor = security_descriptor.pointer if security_descriptor.respond_to?(:pointer)
      present = FFI::Buffer.new :bool
      defaulted = FFI::Buffer.new :bool
      acl = FFI::Buffer.new :pointer
      unless GetSecurityDescriptorDacl(security_descriptor, present, acl, defaulted)
        Win::Error.raise_last_error
      end
      [ present.read_char != 0, ACL.new(acl.read_pointer), defaulted.read_char != 0 ]
    end

    function :GetSecurityDescriptorGroup, [ :pointer, :pointer, :LPBOOL], :BOOL, :dll => "advapi32"
    def self.get_security_descriptor_group(security_descriptor, &block)
      security_descriptor = security_descriptor.pointer if security_descriptor.respond_to?(:pointer)
      result = FFI::Buffer.new :pointer
      defaulted = FFI::Buffer.new :long
      unless GetSecurityDescriptorGroup(security_descriptor, result, defaulted)
        Win::Error.raise_last_error
      end

      sid = SID.new(result.read_pointer)
      defaulted = defaulted.read_char != 0
      if block != nil
        yield sid, defaulted
        free_sid(sid)
      else
        [ sid, defaulted ]
      end
    end

    function :GetSecurityDescriptorOwner, [ :pointer, :pointer, :LPBOOL], :BOOL, :dll => "advapi32"
    def self.get_security_descriptor_owner(security_descriptor, &block)
      security_descriptor = security_descriptor.pointer if security_descriptor.respond_to?(:pointer)
      result = FFI::Buffer.new :pointer
      defaulted = FFI::Buffer.new :long
      unless GetSecurityDescriptorOwner(security_descriptor, result, defaulted)
        Win::Error.raise_last_error
      end

      sid = SID.new(result.read_pointer)
      defaulted = defaulted.read_char != 0
      if block != nil
        yield sid, defaulted
        free_sid(sid)
      else
        [ sid, defaulted ]
      end
    end

    function :GetSecurityDescriptorSacl, [ :pointer, :LPBOOL, :pointer, :LPBOOL ], :BOOL, :dll => "advapi32"
    def self.get_security_descriptor_sacl(security_descriptor)
      security_descriptor = security_descriptor.pointer if security_descriptor.respond_to?(:pointer)
      present = FFI::Buffer.new :bool
      defaulted = FFI::Buffer.new :bool
      acl = FFI::Buffer.new :pointer
      unless GetSecurityDescriptorSacl(security_descriptor, present, acl, defaulted)
        Win::Error.raise_last_error
      end
      [ present.read_char != 0, ACL.new(acl.read_pointer), defaulted.read_char != 0 ]
    end

    function :InitializeAcl, [ :pointer, :DWORD, :DWORD ], :BOOL, :dll => "advapi32"

    function :LookupAccountSid, [ :LPCTSTR, :pointer, :LPTSTR, :LPDWORD, :LPTSTR, :LPDWORD, :pointer ], :BOOL, :dll => "advapi32"
    def self.lookup_account_sid(sid, system_name = nil)
        sid = sid.pointer if sid.respond_to?(:pointer)
        # Figure out how big the buffer needs to be
        name_size = FFI::Buffer.new(:long).write_long(0)
        referenced_domain_name_size = FFI::Buffer.new(:long).write_long(0)
        if LookupAccountSid(system_name, sid, nil, name_size, nil, referenced_domain_name_size, nil)
          raise "Expected error from LookupAccountSid!"
        elsif Win::Error.GetLastError() != Win::Error::ERROR_INSUFFICIENT_BUFFER
          raise "Expected ERROR_INSUFFICIENT_BUFFER from LookupAccountSid!"
        end

        name = FFI::MemoryPointer.new :char, name_size.read_long
        referenced_domain_name = FFI::MemoryPointer.new :char, referenced_domain_name_size.read_long
        use = FFI::Buffer.new(:long).write_long(0)
        unless LookupAccountSid(system_name, sid, name, name_size, referenced_domain_name, referenced_domain_name_size, use)
          Win::Error.raise_last_error
        end

        [ referenced_domain_name.read_string, name.read_string, use.read_long ]
    end
  end
end