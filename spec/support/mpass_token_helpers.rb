# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

module MpassTokenHelpers
  MPASS_TEST_ISSUER    = 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TestPool'.freeze
  MPASS_TEST_CLIENT_ID = 'test-client-id'.freeze
  MPASS_TEST_KID       = 'test-kid'.freeze

  def mpass_signing_key
    @mpass_signing_key ||= OpenSSL::PKey::RSA.generate(2048)
  end

  def mpass_jwks_document(key = mpass_signing_key, kid: MPASS_TEST_KID)
    { keys: [JWT::JWK.new(key, kid: kid).export] }.to_json
  end

  def mpass_access_claims(overrides = {})
    now = Time.now.to_i
    {
      'iss'                 => MPASS_TEST_ISSUER,
      'token_use'           => 'access',
      'client_id'           => MPASS_TEST_CLIENT_ID,
      'iat'                 => now,
      'exp'                 => now + 3600,
      'custom:is_corporate' => 'true',
      'custom:corporate_id' => 'corp-123',
    }.merge(overrides)
  end

  def mpass_token(claims = mpass_access_claims, key: mpass_signing_key, kid: MPASS_TEST_KID, algorithm: 'RS256')
    JWT.encode(claims.compact, key, algorithm, { kid: kid })
  end

  def mpass_static_jwks_cache(document = mpass_jwks_document)
    Zammad::MpassJwksCache.new(fetcher: ->(_url) { document })
  end

  def mpass_test_verifier(jwks_cache: mpass_static_jwks_cache, **overrides)
    Zammad::MpassTokenVerifier.new(
      cognito_issuer: MPASS_TEST_ISSUER,
      client_ids:     [MPASS_TEST_CLIENT_ID],
      jwks_cache:     jwks_cache,
      **overrides,
    )
  end
end

RSpec.configure do |config|
  config.include MpassTokenHelpers, :mpass_token
end
