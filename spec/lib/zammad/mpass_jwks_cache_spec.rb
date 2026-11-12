# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'rails_helper'

RSpec.describe Zammad::MpassJwksCache, :aggregate_failures, :mpass_token do
  let(:issuer)    { MpassTokenHelpers::MPASS_TEST_ISSUER }
  let(:kid)       { MpassTokenHelpers::MPASS_TEST_KID }
  let(:now)       { [1_000.0] }
  let(:fetches)   { [] }
  let(:responses) { [] }
  let(:cache) do
    described_class.new(
      fetcher: lambda { |url|
        fetches << url
        response = responses.empty? ? mpass_jwks_document : responses.shift
        raise response if response.is_a?(Class)

        response
      },
      clock:   -> { now.first },
    )
  end

  def advance(seconds)
    now[0] += seconds
  end

  it 'fetches the JWKS from the issuer well-known path' do
    cache.key_for(issuer, kid)
    expect(fetches).to eq(["#{issuer}/.well-known/jwks.json"])
  end

  it 'caches the key set per issuer' do
    2.times { cache.key_for(issuer, kid) }
    expect(fetches.size).to eq(1)
  end

  it 'refetches after the lifespan' do
    cache.key_for(issuer, kid)
    advance(described_class::LIFESPAN_SECONDS)
    cache.key_for(issuer, kid)
    expect(fetches.size).to eq(2)
  end

  it 'refetches for an unknown kid at most once per refresh interval' do
    cache.key_for(issuer, kid)
    advance(described_class::MIN_REFRESH_INTERVAL)
    2.times { expect(cache.key_for(issuer, 'rotated')).to be_nil }
    expect(fetches.size).to eq(2)
  end

  it 'raises Unavailable and backs off after a failed fetch' do
    responses << Net::OpenTimeout
    expect { cache.key_for(issuer, kid) }.to raise_error(described_class::Unavailable)
    expect { cache.key_for(issuer, kid) }.to raise_error(described_class::Unavailable)
    expect(fetches.size).to eq(1)
  end

  it 'retries once the backoff has passed' do
    responses << Net::OpenTimeout
    expect { cache.key_for(issuer, kid) }.to raise_error(described_class::Unavailable)
    advance(described_class::FAILURE_BACKOFF_SECONDS)
    expect(cache.key_for(issuer, kid)).to be_a(OpenSSL::PKey::RSA)
  end

  it 'treats a document without keys as unavailable' do
    responses << '{"error":"nope"}'
    expect { cache.key_for(issuer, kid) }.to raise_error(described_class::Unavailable)
  end
end
