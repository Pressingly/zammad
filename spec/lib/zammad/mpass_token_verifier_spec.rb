# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe Zammad::MpassTokenVerifier, :mpass_token do
  let(:verifier) { mpass_test_verifier }

  def rejection_reason(token, subject_verifier = verifier)
    subject_verifier.verify(token)
    nil
  rescue described_class::InvalidToken => e
    e.reason
  end

  describe '#verify' do
    it 'returns the claims of a valid Cognito access token' do
      expect(verifier.verify(mpass_token)).to include('custom:corporate_id' => 'corp-123')
    end

    it 'accepts an id_token whose aud contains the client id' do
      claims = mpass_access_claims('token_use' => 'id', 'client_id' => nil, 'aud' => MpassTokenHelpers::MPASS_TEST_CLIENT_ID)
      expect(rejection_reason(mpass_token(claims))).to be_nil
    end

    it 'accepts an id_token signed by the allowlisted mpass-auth-proxy issuer' do
      proxy_issuer = 'https://auth.example.test'
      proxy_key    = OpenSSL::PKey::RSA.generate(2048)
      documents    = {
        Zammad::MpassJwksCache.jwks_url(MpassTokenHelpers::MPASS_TEST_ISSUER) => mpass_jwks_document,
        Zammad::MpassJwksCache.jwks_url(proxy_issuer)                         => mpass_jwks_document(proxy_key, kid: 'proxy-kid'),
      }
      two_issuers = mpass_test_verifier(
        jwks_cache:    Zammad::MpassJwksCache.new(fetcher: ->(url) { documents.fetch(url) }),
        extra_issuers: [proxy_issuer],
      )
      claims = mpass_access_claims('iss' => proxy_issuer, 'token_use' => 'id', 'client_id' => nil, 'aud' => [MpassTokenHelpers::MPASS_TEST_CLIENT_ID])

      expect(rejection_reason(mpass_token(claims, key: proxy_key, kid: 'proxy-kid'), two_issuers)).to be_nil
    end

    it 'accepts an access token issued to an additional client id such as the MCP client' do
      mcp_verifier = mpass_test_verifier(client_ids: [MpassTokenHelpers::MPASS_TEST_CLIENT_ID, 'mcp-client'])
      expect(rejection_reason(mpass_token(mpass_access_claims('client_id' => 'mcp-client')), mcp_verifier)).to be_nil
    end

    it 'rejects a token signed by another key' do
      forged = mpass_token(key: OpenSSL::PKey::RSA.generate(2048))
      expect(rejection_reason(forged)).to eq('bad_signature')
    end

    it 'rejects a token with a tampered payload' do
      header, _payload, signature = mpass_token.split('.')
      tampered = Base64.urlsafe_encode64(mpass_access_claims('custom:corporate_id' => 'other').to_json, padding: false)
      expect(rejection_reason([header, tampered, signature].join('.'))).to eq('bad_signature')
    end

    it 'rejects an expired token' do
      expired = mpass_access_claims('iat' => Time.now.to_i - 7200, 'exp' => Time.now.to_i - 120)
      expect(rejection_reason(mpass_token(expired))).to eq('expired')
    end

    it 'tolerates clock skew within the leeway' do
      skewed = mpass_access_claims('exp' => Time.now.to_i - 30, 'iat' => Time.now.to_i + 30)
      expect(rejection_reason(mpass_token(skewed))).to be_nil
    end

    it 'rejects a token issued in the future beyond the leeway' do
      expect(rejection_reason(mpass_token(mpass_access_claims('iat' => Time.now.to_i + 600)))).to eq('invalid')
    end

    it 'rejects a token from an issuer that is not allowlisted' do
      expect(rejection_reason(mpass_token(mpass_access_claims('iss' => 'https://evil.example.test')))).to eq('untrusted_issuer')
    end

    it 'rejects an access token for another client' do
      expect(rejection_reason(mpass_token(mpass_access_claims('client_id' => 'other-client')))).to eq('wrong_audience')
    end

    it 'rejects an id_token for another audience' do
      claims = mpass_access_claims('token_use' => 'id', 'client_id' => nil, 'aud' => 'other-client')
      expect(rejection_reason(mpass_token(claims))).to eq('wrong_audience')
    end

    it 'rejects an unknown token_use' do
      expect(rejection_reason(mpass_token(mpass_access_claims('token_use' => 'refresh')))).to eq('wrong_audience')
    end

    %w[exp iat iss token_use].each do |claim|
      it "rejects a token without #{claim}" do
        expect(rejection_reason(mpass_token(mpass_access_claims(claim => nil)))).to be_present
      end
    end

    it 'rejects an unsigned alg=none token' do
      header  = Base64.urlsafe_encode64({ alg: 'none', kid: MpassTokenHelpers::MPASS_TEST_KID }.to_json, padding: false)
      payload = Base64.urlsafe_encode64(mpass_access_claims.to_json, padding: false)
      expect(rejection_reason("#{header}.#{payload}.")).to eq('invalid')
    end

    it 'rejects an HS256 token keyed with the public key' do
      hs256 = mpass_token(key: mpass_signing_key.public_key.to_pem, algorithm: 'HS256')
      expect(rejection_reason(hs256)).to eq('invalid')
    end

    it 'rejects a token whose kid is not in the JWKS' do
      expect(rejection_reason(mpass_token(kid: 'unknown-kid'))).to eq('unknown_signing_key')
    end

    it 'rejects a malformed token' do
      expect(rejection_reason('not-a-jwt')).to eq('malformed')
    end

    it 'rejects every token when unconfigured' do
      unconfigured = mpass_test_verifier(client_ids: [])
      expect(rejection_reason(mpass_token, unconfigured)).to eq('verifier_unconfigured')
    end

    it 'rejects with jwks_unavailable when the JWKS fetch fails' do
      failing = Zammad::MpassJwksCache.new(fetcher: ->(_url) { raise Net::OpenTimeout })
      expect(rejection_reason(mpass_token, mpass_test_verifier(jwks_cache: failing))).to eq('jwks_unavailable')
    end

    it 'rejects with jwks_unavailable when the JWKS document is not JSON' do
      garbled = Zammad::MpassJwksCache.new(fetcher: ->(_url) { '<html>' })
      expect(rejection_reason(mpass_token, mpass_test_verifier(jwks_cache: garbled))).to eq('jwks_unavailable')
    end
  end

  describe '.from_env' do
    let(:pool_env) { { 'COGNITO_AWS_REGION' => 'eu-west-1', 'COGNITO_USER_POOL_ID' => 'eu-west-1_Pool', 'MPASS_OIDC_CLIENT_ID' => 'cid' } }

    it 'uses MPASS_COGNITO_ISSUER_URL without its trailing slash' do
      expect(described_class.cognito_issuer('MPASS_COGNITO_ISSUER_URL' => 'https://issuer.example.test/')).to eq('https://issuer.example.test')
    end

    it 'falls back to the region and pool id' do
      expect(described_class.cognito_issuer(pool_env)).to eq('https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Pool')
    end

    it 'treats CHANGE_ME_ placeholders as unset' do
      env = pool_env.merge('MPASS_COGNITO_ISSUER_URL' => 'CHANGE_ME_ISSUER', 'COGNITO_USER_POOL_ID' => 'CHANGE_ME_POOL')
      expect(described_class.cognito_issuer(env)).to eq('')
    end

    it 'is configured with an issuer and a client id' do
      expect(described_class.from_env(pool_env)).to be_configured
    end

    it 'is not configured without a client id' do
      expect(described_class.from_env(pool_env.except('MPASS_OIDC_CLIENT_ID'))).not_to be_configured
    end

    it 'is not configured with only the mpass-auth-proxy issuer' do
      env = { 'MPASS_TOKEN_ISSUER_URL' => 'https://auth.example.test', 'MPASS_OIDC_CLIENT_ID' => 'cid' }
      expect(described_class.from_env(env)).not_to be_configured
    end
  end
end
