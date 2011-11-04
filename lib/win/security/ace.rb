require 'win/security'
require 'win/security/sid'
require 'ffi'

module Win
  module Security
    class ACE
      def initialize(pointer)
        if Win::Security::ACE_WITH_MASK_AND_SID.supports?(pointer.read_uchar)
          @struct = Win::Security::ACE_WITH_MASK_AND_SID.new pointer
        else
          # TODO Support ALL the things
          @struct = Win::Security::ACE_HEADER.new pointer
        end
      end

      attr_reader :struct

      def pointer
        struct.pointer
      end

      def type
        struct[:AceType]
      end

      def flags
        struct[:AceFlags]
      end

      def mask
        struct[:Mask]
      end

      def sid
        # The SID runs off the end of the structure, starting at :SidStart.
        # Use pointer arithmetic to get a pointer to that location.
        SID.new(struct.pointer + struct.offset_of(:SidStart))
      end

      def inherited?
        (struct[:AceFlags] & INHERITED_ACE) != 0
      end

      def explicit?
        ! inherited?
      end
    end
  end
end