module Win
  module Security
    class SID
      def initialize(pointer)
        # TODO I think we're leaking this
        @pointer = pointer
      end

      attr_reader :pointer

      def account
        Win::Security::lookup_account_sid(pointer)
      end

      def account_name
        domain, name, use = account
        domain ? "#{domain}\\#{name}" : name
      end
    end
  end
end