require 'win/security'
require 'win/security/ace'
require 'ffi'

module Win
  module Security
    class ACL
      include Enumerable

      def initialize(pointer)
        @struct = Win::Security::ACLStruct.new pointer
      end

      def self.create(aces, &block)
        aces_size = aces.inject(0) { |sum,ace| sum + ace.size }
        acl_size = align_dword(ACLStruct.size + aces_size)
        acl = Win::Memory.local_alloc(acl_size)

        unless Win::Security::InitializeAcl(acl, acl_size, ACL_REVISION)
          Win::Error.raise_last_error
        end

        aces.each { |ace| Win::Security.add_ace(acl, ace) }

        yield ACL.new(acl)

        Win::Memory.local_free(acl)
      end

      attr_reader :struct

      def pointer
        struct.pointer
      end

      def [](index)
        Win::Security::get_ace(pointer, index)
      end

      def delete_at(index)
        Win::Security.delete_ace(pointer, index)
      end

      def each
        0.upto(length-1) { |i| yield self[i] }
      end

      def insert(index, *aces)
        aces.reverse_each { |ace| Win::Security.add_ace(pointer, ace, index) }
      end

      def length
        struct[:AceCount]
      end

      def push(*aces)
        aces.each { |ace| Win::Security.add_ace(self, ace) }
      end

      def unshift(*aces)
        aces.each { |ace| Win::Security.add_ace(pointer, ace, 0) }
      end

      private

      def self.align_dword(size)
        (size + 4 - 1) & 0xfffffffc
      end
    end
  end
end
