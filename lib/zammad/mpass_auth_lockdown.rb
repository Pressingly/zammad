# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

module Zammad
  module MpassAuthLockdown
    module UserEmailImmutable
      extend ActiveSupport::Concern

      included do
        validate :prevent_email_change_under_sso, on: :update
      end

      private

      def prevent_email_change_under_sso
        return unless ENV['AUTH_TYPE'] == 'SSO' # rubocop:disable Rails/EnvironmentVariableAccess
        return unless email_changed?
        return if UserInfo.current_user_id == 1

        errors.add(:email, __('is managed by SSO and cannot be changed'))
      end
    end

    module RejectPasswordChange
      def execute
        if ENV['AUTH_TYPE'] == 'SSO' # rubocop:disable Rails/EnvironmentVariableAccess
          raise Exceptions::Forbidden, __('Password management is disabled when SSO is active.')
        end

        super
      end
    end
  end
end
