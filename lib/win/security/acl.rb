require 'win/security'
require 'win/security/ace'
require 'ffi'

module Win
  module Security
    class ACL
      include Enumerable

      def initialize(pointer, owner = nil)
        @struct = Win::Security::ACLStruct.new pointer
        # Keep a reference to the actual owner of this memory so that it isn't freed out from under us
        # TODO this could be avoided if we could mark a pointer's parent manually
        @owner = owner
      end

      def self.create(aces)
        aces_size = aces.inject(0) { |sum,ace| sum + ace.size }
        acl_size = align_dword(ACLStruct.size + aces_size) # What the heck is 94???
        acl = Win::Security.initialize_acl(acl_size)
        aces.each { |ace| Win::Security.add_ace(acl, ace) }
        acl
      end

      attr_reader :struct

      def pointer
        struct.pointer
      end

      def [](index)
        Win::Security::get_ace(self, index)
      end

      def delete_at(index)
        Win::Security.delete_ace(self, index)
      end

      def each
        0.upto(length-1) { |i| yield self[i] }
      end

      def insert(index, *aces)
        aces.reverse_each { |ace| Win::Security.add_ace(self, ace, index) }
      end

      def length
        struct[:AceCount]
      end

      def push(*aces)
        aces.each { |ace| Win::Security.add_ace(self, ace) }
      end

      def unshift(*aces)
        aces.each { |ace| Win::Security.add_ace(self, ace, 0) }
      end

      def valid?
        Win::Security.is_valid_acl(self)
      end

      private

      def self.align_dword(size)
        (size + 4 - 1) & 0xfffffffc
      end
    end
  end
end
