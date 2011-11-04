module Win
  module Security
    class SID
      def initialize(pointer)
        @pointer = pointer
      end

      def self.from_account(name)
        domain, sid, use = Win::Security::lookup_account_name(name)
        sid
      end

      attr_reader :pointer

      def account
        Win::Security::lookup_account_sid(pointer)
      end

      def account_name
        domain, name, use = account
        domain ? "#{domain}\\#{name}" : name
      end

      def size
        Win::Security::get_length_sid(pointer)
      end
    end
  end
end