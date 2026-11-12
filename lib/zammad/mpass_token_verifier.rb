# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'jwt'
require 'zammad/mpass_edge_trust'
require 'zammad/mpass_jwks_cache'

module Zammad
  # Verifies the mPass token oauth2-proxy forwards in X-Auth-Request-Access-Token.
  #
  # A browser session forwards the Cognito access token; mpass-auth-proxy
  # re-signs id_tokens under its own issuer when email capture is on. Both
  # issuers are trusted, each against its own JWKS, and nothing else is.
  class MpassTokenVerifier
    ALGORITHM       = 'RS256'.freeze
    LEEWAY_SECONDS  = 60
    REQUIRED_CLAIMS = %w[exp iat iss token_use].freeze

    class InvalidToken < StandardError
      attr_reader :reason

      def initialize(reason)
        super
        @reason = reason
      end
    end

    def self.configured(value)
      MpassEdgeTrust.configured(value)
    end

    def self.cognito_issuer(env)
      explicit = configured(env['MPASS_COGNITO_ISSUER_URL']).chomp('/')
      return explicit if explicit.present?

      region  = configured(env['COGNITO_AWS_REGION'])
      pool_id = configured(env['COGNITO_USER_POOL_ID'])
      return '' if region.blank? || pool_id.blank?

      "https://cognito-idp.#{region}.amazonaws.com/#{pool_id}"
    end

    def self.from_env(env = ENV)
      new(
        cognito_issuer: cognito_issuer(env),
        extra_issuers:  [configured(env['MPASS_TOKEN_ISSUER_URL']).chomp('/')],
        client_ids:     [configured(env['MPASS_OIDC_CLIENT_ID']), configured(env['MPASS_MCP_OIDC_CLIENT_ID'])],
      )
    end

    def self.audience_matches?(claims, client_ids)
      case claims['token_use']
      when 'access'
        client_ids.include?(claims['client_id'])
      when 'id'
        Array.wrap(claims['aud']).intersect?(client_ids)
      else
        false
      end
    end

    def initialize(cognito_issuer:, client_ids:, extra_issuers: [], jwks_cache: MpassJwksCache.new, clock: -> { Time.now.to_i })
      @cognito_issuer = cognito_issuer.to_s
      @issuers        = [@cognito_issuer, *extra_issuers].compact_blank.uniq.freeze
      @client_ids     = client_ids.compact_blank.uniq.freeze
      @jwks_cache     = jwks_cache
      @clock          = clock
    end

    def configured?
      @cognito_issuer.present? && @client_ids.any?
    end

    def verify(token)
      raise InvalidToken, 'verifier_unconfigured' if !configured?

      payload, header = unverified_segments(token)
      issuer = payload['iss'].to_s
      raise InvalidToken, 'untrusted_issuer' if @issuers.exclude?(issuer)

      claims = decode(token, signing_key(issuer, header['kid']), issuer)
      raise InvalidToken, 'invalid' if issued_in_future?(claims)
      raise InvalidToken, 'wrong_audience' if !self.class.audience_matches?(claims, @client_ids)

      claims
    end

    private

    def unverified_segments(token)
      payload, header = JWT.decode(token, nil, false)
      raise InvalidToken, 'malformed' if !payload.is_a?(Hash) || !header.is_a?(Hash)

      [payload, header]
    rescue JWT::DecodeError
      raise InvalidToken, 'malformed'
    end

    def signing_key(issuer, kid)
      key = @jwks_cache.key_for(issuer, kid)
      raise InvalidToken, 'unknown_signing_key' if key.nil?

      key
    rescue MpassJwksCache::Unavailable
      raise InvalidToken, 'jwks_unavailable'
    end

    def decode(token, key, issuer)
      JWT.decode(token, key, true,
                 algorithms:      [ALGORITHM],
                 iss:             issuer,
                 verify_iss:      true,
                 required_claims: REQUIRED_CLAIMS,
                 leeway:          LEEWAY_SECONDS).first
    rescue JWT::ExpiredSignature
      raise InvalidToken, 'expired'
    rescue JWT::InvalidIssuerError
      raise InvalidToken, 'untrusted_issuer'
    rescue JWT::VerificationError
      raise InvalidToken, 'bad_signature'
    rescue JWT::DecodeError
      raise InvalidToken, 'invalid'
    end

    def issued_in_future?(claims)
      !claims['iat'].is_a?(Numeric) || claims['iat'] > @clock.call + LEEWAY_SECONDS
    end
  end
end
