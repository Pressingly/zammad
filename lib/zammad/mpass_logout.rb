# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'uri'

module Zammad
  # Plumbing for the platform-wide logout rule.
  #
  # Under platform SSO the per-app "Sign out" control is navigation-only: it
  # takes the user back to the platform portal and must not clear any session.
  # Clearing the local session would be pointless anyway, because
  # Zammad::MpassProxyAuth re-establishes it from the X-Auth-Request-Email
  # header on the very next request.
  #
  # The portal URL is supplied by the deployment environment
  # (LOGOUT_REDIRECT_URL) and mirrored into frontend Settings at boot, so the
  # very same precompiled image can serve any client. It is deliberately not
  # derived from the request host and not baked in at build time.
  module MpassLogout
    SSO_SETTING_NAME      = 'mpass_sso_active'.freeze
    REDIRECT_SETTING_NAME = 'mpass_logout_redirect_url'.freeze
    ENV_NAME              = 'LOGOUT_REDIRECT_URL'.freeze

    class << self
      # Create both frontend Settings if they are missing and sync their state
      # with the current environment. Safe to call on every boot, and a no-op
      # when no database or settings table is available yet (migrations, asset
      # precompilation, rake tasks on a fresh install).
      #
      # @return [Boolean] true when the Settings are in sync afterwards.
      def sync_settings!
        return false if !settings_table_available?

        create_settings_if_missing

        # Each assign is isolated. Sharing one rescue would let a failure on the
        # first setting skip the second, and both half-states are worse than the
        # bug this fixes: sso_active=false silently restores stock logout (which
        # MpassProxyAuth immediately undoes), and sso_active=true with a blank
        # URL makes Sign out do nothing at all.
        ok_sso      = assign(SSO_SETTING_NAME, sso?)
        ok_redirect = assign(REDIRECT_SETTING_NAME, configured_url)

        ok_sso && ok_redirect
      end

      # @return [Boolean] true when the setting holds the wanted value afterwards.
      def assign(name, value)
        return true if Setting.get(name) == value

        Setting.set(name, value)
        true
      rescue ActiveRecord::ActiveRecordError => e
        Rails.logger.error("mpass_logout: could not set #{name}: #{e.message}")
        false
      end

      # The portal URL that "Sign out" navigates to.
      #
      # @return [String] a validated absolute http(s) URL, or an empty string
      #   when SSO is inactive, the variable is unset, or the value is unusable.
      def configured_url
        return '' if !sso?

        raw = ENV[ENV_NAME].to_s.strip # rubocop:disable Rails/EnvironmentVariableAccess

        if raw.empty?
          Rails.logger.error("mpass_logout: #{ENV_NAME} is not set — the per-app sign out control will do nothing")
          return ''
        end

        return raw if valid_url?(raw)

        Rails.logger.error("mpass_logout: #{ENV_NAME}=#{raw.inspect} is not an absolute http(s) URL — ignoring it")
        ''
      end

      private

      def sso?
        ENV['AUTH_TYPE'] == 'SSO' # rubocop:disable Rails/EnvironmentVariableAccess
      end

      def valid_url?(value)
        uri = URI.parse(value)
        uri.is_a?(URI::HTTP) && uri.host.present?
      rescue URI::InvalidURIError
        false
      end

      def settings_table_available?
        ActiveRecord::Base.connection_pool.with_connection { |connection| connection.table_exists?('settings') }
      rescue ActiveRecord::ConnectionNotEstablished, ActiveRecord::NoDatabaseError, ActiveRecord::StatementInvalid
        false
      end

      # Each create is independently rescued: the check-then-act in
      # Setting.exists? -> create_if_not_exists can lose a race (RecordNotUnique),
      # and a failure on one setting must not prevent the other from existing.
      def create_settings_if_missing
        %i[create_sso_setting create_redirect_setting].each do |creator|
          send(creator)
        rescue ActiveRecord::ActiveRecordError => e
          Rails.logger.error("mpass_logout: could not create setting via #{creator}: #{e.message}")
        end
      end

      def create_sso_setting
        return if Setting.exists?(name: SSO_SETTING_NAME)

        Setting.create_if_not_exists(
          title:       'Platform SSO Active',
          name:        SSO_SETTING_NAME,
          area:        'Core',
          description: 'Defines if the platform SSO integration (AUTH_TYPE=SSO) is active. Managed by the deployment environment, not by administrators.',
          options:     {},
          state:       false,
          preferences: {},
          frontend:    true
        )
      end

      def create_redirect_setting
        return if Setting.exists?(name: REDIRECT_SETTING_NAME)

        Setting.create_if_not_exists(
          title:       'Logout Redirect URL',
          name:        REDIRECT_SETTING_NAME,
          area:        'Core',
          description: 'Platform portal URL that the per-app sign out control navigates to. Managed by the deployment environment (LOGOUT_REDIRECT_URL), not by administrators.',
          options:     {},
          state:       '',
          preferences: {},
          frontend:    true
        )
      end
    end
  end
end
