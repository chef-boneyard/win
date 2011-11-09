require 'win/security'
require 'win/security/sid'
require 'ffi'

module Win
  module Security
    class ACE
      def initialize(pointer, owner = nil)
        if Win::Security::ACE_WITH_MASK_AND_SID.supports?(pointer.read_uchar)
          @struct = Win::Security::ACE_WITH_MASK_AND_SID.new pointer
        else
          # TODO Support ALL the things
          @struct = Win::Security::ACE_HEADER.new pointer
        end
        # Keep a reference to the actual owner of this memory so we don't get freed
        @owner = owner
      end

      def self.size_with_sid(sid)
        Win::Security::ACE_WITH_MASK_AND_SID.offset_of(:SidStart) + sid.size
      end

      def self.access_allowed(sid, access_mask, flags = 0)
        create_ace_with_mask_and_sid(Win::Security::ACCESS_ALLOWED_ACE_TYPE, flags, access_mask, sid)
      end

      def self.access_denied(sid, access_mask, flags = 0)
        create_ace_with_mask_and_sid(Win::Security::ACCESS_DENIED_ACE_TYPE, flags, access_mask, sid)
      end

      attr_reader :struct

      def flags
        struct[:AceFlags]
      end

      def flags=(val)
        struct[:AceFlags] = val
      end

      def explicit?
        ! inherited?
      end

      def inherited?
        (struct[:AceFlags] & INHERITED_ACE) != 0
      end

      def mask
        struct[:Mask]
      end

      def mask=(val)
        struct[:Mask] = val
      end

      def pointer
        struct.pointer
      end

      def size
        struct[:AceSize]
      end

      def sid
        # The SID runs off the end of the structure, starting at :SidStart.
        # Use pointer arithmetic to get a pointer to that location.
        SID.new(struct.pointer + struct.offset_of(:SidStart))
      end

      def type
        struct[:AceType]
      end

      private

      def self.create_ace_with_mask_and_sid(type, flags, mask, sid)
        size_needed = size_with_sid(sid)
        pointer = FFI::MemoryPointer.new size_needed
        struct = Win::Security::ACE_WITH_MASK_AND_SID.new pointer
        struct[:AceType] = type
        struct[:AceFlags] = flags
        struct[:AceSize] = size_needed
        struct[:Mask] = mask
        Win::Memory.memcpy(struct.pointer + struct.offset_of(:SidStart), sid.pointer, sid.size)
        ACE.new(struct.pointer)
      end
    end
  end
end