# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'json'
require 'zammad/mpass_edge_trust'
require 'zammad/mpass_token_verifier'

module Zammad
  # Signs in the user oauth2-proxy asserts in X-Auth-Request-Email.
  #
  # The identity headers are honoured only on requests carrying MPASS_EDGE_SECRET
  # in X-Mpass-Edge-Secret, which Traefik sets on the SSO router. On any other
  # request they are dropped before anything reads them, and Zammad's own
  # authentication (session cookie, API token) applies.
  class MpassProxyAuth
    EMAIL_HEADER        = 'HTTP_X_AUTH_REQUEST_EMAIL'.freeze
    ACCESS_TOKEN_HEADER = 'HTTP_X_AUTH_REQUEST_ACCESS_TOKEN'.freeze
    MPASS_ID_HEADERS    = %w[HTTP_X_AUTH_REQUEST_USER HTTP_X_AUTH_REQUEST_PREFERRED_USERNAME].freeze
    IDENTITY_HEADER_PREFIX = 'HTTP_X_AUTH_REQUEST_'.freeze

    def self.identity_header_keys(env)
      env.keys.select { |key| key.is_a?(String) && key.start_with?(IDENTITY_HEADER_PREFIX) }
    end

    # With email capture on X-Auth-Request-User carries the email, so only a value without '@' is logged.
    def self.mpass_id_for_logs(env)
      MPASS_ID_HEADERS.map { |header| env[header].to_s.strip }.find { |value| value.present? && value.exclude?('@') } || '-'
    end

    def initialize(app,
                   edge_secret:    MpassEdgeTrust.configured(ENV['MPASS_EDGE_SECRET']),
                   corporate_id:   ENV['SMB_CORPORATE_ID'].to_s.strip,
                   token_verifier: MpassTokenVerifier.from_env)
      @app            = app
      @edge_secret    = edge_secret
      @corporate_id   = corporate_id
      @token_verifier = token_verifier
      log_configuration_errors
    end

    def call(env)
      from_edge = MpassEdgeTrust.from_edge?(env, @edge_secret)
      env.delete(MpassEdgeTrust::HEADER)
      drop_untrusted_identity_headers(env) if !from_edge

      email_claim = env[EMAIL_HEADER]
      return @app.call(env) if email_claim.blank?

      sign_in(env, email_claim)
    end

    private

    def log_configuration_errors
      if !MpassEdgeTrust.usable_secret?(@edge_secret)
        Rails.logger.error('mpass_proxy_auth: MPASS_EDGE_SECRET is unset or shorter than 32 characters: mPass identity headers will be ignored and SSO login is disabled')
      end
      return if !corporate_gate_active? || @token_verifier.configured?

      Rails.logger.error('mpass_proxy_auth: SMB_CORPORATE_ID is set but no token issuer or client id is configured (MPASS_COGNITO_ISSUER_URL, MPASS_OIDC_CLIENT_ID): every mPass login will be refused')
    end

    def drop_untrusted_identity_headers(env)
      keys = self.class.identity_header_keys(env)
      return if keys.empty?

      Rails.logger.warn("mpass_proxy_auth: mPass identity headers ignored: request lacks the edge secret mpass_id=#{self.class.mpass_id_for_logs(env)} path=#{env['PATH_INFO']} remote_addr=#{env['REMOTE_ADDR'] || '-'} forwarded_for=#{env['HTTP_X_FORWARDED_FOR'] || '-'}")
      keys.each { |key| env.delete(key) }
    end

    def sign_in(env, email_claim)
      email = resolve_email(email_claim)
      return forbidden('DEFAULT_EMAIL_DOMAIN is required but not set') if email.nil?

      session = env['rack.session']
      user = find_user(email)
      if !session_holds?(session, user)
        rejection = corporate_rejection(env)
        return refuse_login(env, rejection) if rejection

        user ||= create_user_safely(email)
      end

      return forbidden(__('User could not be resolved')) if user.nil?
      return forbidden(__('User account is not active')) if !user.active
      return forbidden(__('Maintenance mode enabled!')) if maintenance_mode?(user)
      return @app.call(env) if session_holds?(session, user)

      if session[:user_id]
        Rails.logger.info { "mpass_proxy_auth: session re-key from user #{session[:user_id]} to #{user.id}" }
      end

      establish_session(session, user)
      @app.call(env)
    end

    # The corporate gate runs when a session is opened, as in Plane: the
    # forwarded token is checked once per login, not on every request.
    def session_holds?(session, user)
      !user.nil? && session[:user_id] == user.id
    end

    def refuse_login(env, rejection)
      Rails.logger.warn("mpass_proxy_auth: mPass login refused reason=#{rejection} mpass_id=#{self.class.mpass_id_for_logs(env)} path=#{env['PATH_INFO']}")
      forbidden('access_denied')
    end

    def resolve_email(claim)
      claim = claim.to_s.strip.downcase
      return nil if claim.empty?
      return claim if claim.include?('@')

      domain = ENV['DEFAULT_EMAIL_DOMAIN']
      if domain.blank?
        Rails.logger.error('mpass_proxy_auth: bare username received but DEFAULT_EMAIL_DOMAIN is not set — failing closed')
        return nil
      end
      "#{claim}@#{domain}"
    end

    def maintenance_mode?(user)
      Setting.get('maintenance_mode') == true && !user.permissions?('admin.maintenance')
    end

    def corporate_gate_active?
      @corporate_id.present?
    end

    # Why the caller fails the SMB corporate gate, or nil when it passes. With
    # SMB_CORPORATE_ID unset the gate is off and the token is never read.
    def corporate_rejection(env)
      return nil if !corporate_gate_active?

      access_token = env[ACCESS_TOKEN_HEADER]
      return 'missing_token' if access_token.blank?

      corporate_claims_rejection(@token_verifier.verify(access_token))
    rescue MpassTokenVerifier::InvalidToken => e
      e.reason
    end

    def corporate_claims_rejection(claims)
      return 'not_corporate' if claims['custom:is_corporate'] != 'true'
      return 'wrong_organization' if claims['custom:corporate_id'] != @corporate_id

      nil
    end

    def find_user(email)
      User.find_by(login: email) || User.find_by(email: email)
    end

    def create_user_safely(email)
      UserInfo.with_user_id(1) { find_user(email) || create_user(email) }
    rescue => e
      Rails.logger.error("mpass_proxy_auth: user upsert failed for #{email}: #{e.message}")
      nil
    end

    def create_user(email)
      local_part = email.split('@').first

      # Every SSO user is provisioned as a plain signup user (Customer). Role is
      # deliberately NOT derived from the email domain: DEFAULT_EMAIL_DOMAIN is
      # the platform's *synthetic* domain for users with no verified email, so
      # keying Agent off it would grant elevated access to exactly the
      # unverified population. Agents and admins are granted out of band by the
      # bundle's provision-workspaces-admin.sh.
      User.create!(
        login:         email,
        email:         email,
        firstname:     local_part&.capitalize,
        lastname:      '',
        active:        true,
        role_ids:      Role.signup_role_ids,
        updated_by_id: 1,
        created_by_id: 1,
      )
    end

    def establish_session(session, user)
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
