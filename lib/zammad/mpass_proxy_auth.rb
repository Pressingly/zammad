# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'base64'
require 'json'

module Zammad
  class MpassProxyAuth
    EMAIL_HEADER          = 'HTTP_X_AUTH_REQUEST_EMAIL'
    ACCESS_TOKEN_HEADER   = 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'

    def initialize(app)
      @app = app
    end

    def call(env)
      email_claim = env[EMAIL_HEADER]

      if email_claim.blank?
        return @app.call(env)
      end

      email = resolve_email(email_claim)
      return forbidden('DEFAULT_EMAIL_DOMAIN is required but not set') if email.nil?

      if corporate_id_enforcement_active?
        denial = check_corporate_id(env)
        return denial if denial
      end

      session = env['rack.session']
      user = upsert_user(email)

      return forbidden('User could not be resolved') if user.nil?
      return forbidden('User account is not active') unless user.active

      if maintenance_mode?(user)
        return forbidden('Maintenance mode enabled!')
      end

      existing_user_id = session[:user_id]

      if existing_user_id && existing_user_id == user.id
        return @app.call(env)
      end

      if existing_user_id && existing_user_id != user.id
        Rails.logger.info { "mpass_proxy_auth: session re-key from user #{existing_user_id} to #{user.id}" }
      end

      establish_session(env, session, user)

      @app.call(env)
    end

    private

    def resolve_email(claim)
      claim = claim.to_s.strip.downcase
      return nil if claim.empty?

      if claim.include?('@')
        claim
      else
        domain = ENV['DEFAULT_EMAIL_DOMAIN'] # rubocop:disable Rails/EnvironmentVariableAccess
        if domain.blank?
          Rails.logger.error('mpass_proxy_auth: bare username received but DEFAULT_EMAIL_DOMAIN is not set — failing closed')
          return nil
        end
        "#{claim}@#{domain}"
      end
    end

    def maintenance_mode?(user)
      Setting.get('maintenance_mode') == true && !user.permissions?('admin.maintenance')
    end

    def corporate_id_enforcement_active?
      ENV['SMB_CORPORATE_ID'].present? # rubocop:disable Rails/EnvironmentVariableAccess
    end

    def check_corporate_id(env)
      access_token = env[ACCESS_TOKEN_HEADER]

      if access_token.blank?
        Rails.logger.warn('mpass_proxy_auth: corporate-id enforcement active but no access token present')
        return forbidden('access_denied')
      end

      parts = access_token.split('.')
      return forbidden('access_denied') if parts.length < 2

      payload = begin
        decoded = Base64.urlsafe_decode64(parts[1])
        JSON.parse(decoded)
      rescue StandardError => e
        Rails.logger.warn("mpass_proxy_auth: failed to decode access token payload: #{e.message}")
        return forbidden('access_denied')
      end

      expected = ENV['SMB_CORPORATE_ID'] # rubocop:disable Rails/EnvironmentVariableAccess
      is_corporate = payload['custom:is_corporate']
      corporate_id = payload['custom:corporate_id']

      if is_corporate != 'true' || corporate_id != expected
        Rails.logger.warn("mpass_proxy_auth: corporate-id mismatch — expected=#{expected}, got=#{corporate_id}, is_corporate=#{is_corporate}")
        return forbidden('access_denied')
      end

      nil
    end

    def upsert_user(email)
      UserInfo.with_user_id(1) do
        user = User.find_by(login: email) || User.find_by(email: email)

        if user
          maybe_promote_role(user, email)
          return user
        end

        create_user(email)
      end
    rescue StandardError => e
      Rails.logger.error("mpass_proxy_auth: user upsert failed for #{email}: #{e.message}")
      nil
    end

    def create_user(email)
      local_part = email.split('@').first
      agent_role = Role.find_by(name: 'Agent')

      role_ids = if corporate_email?(email)
                   [agent_role&.id].compact
                 else
                   Role.signup_role_ids
                 end

      User.create!(
        login:         email,
        email:         email,
        firstname:     local_part&.capitalize,
        lastname:      '',
        active:        true,
        role_ids:      role_ids,
        updated_by_id: 1,
        created_by_id: 1,
      )
    end

    def maybe_promote_role(user, email)
      return unless corporate_email?(email)

      agent_role = Role.find_by(name: 'Agent')
      return if agent_role.nil?
      return if user.role?('Agent')

      user.role_ids = (user.role_ids + [agent_role.id]).uniq
      user.save!

      Rails.logger.info("mpass_proxy_auth: promoted user #{user.id} (#{email}) to Agent")
    end

    def corporate_email?(email)
      domain = ENV['DEFAULT_EMAIL_DOMAIN'] # rubocop:disable Rails/EnvironmentVariableAccess
      return false if domain.blank?

      email.end_with?("@#{domain}")
    end

    def establish_session(env, session, user)
      session.delete(:switched_from_user_id)
      session[:user_id] = user.id
      session[:persistent] = true
      session[:authentication_type] = 'SSO'
    end

    def forbidden(message)
      body = JSON.generate(error: message)
      [403, { 'content-type' => 'application/json' }, [body]]
    end
  end
end
