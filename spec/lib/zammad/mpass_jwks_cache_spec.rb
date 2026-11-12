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
      logger:  logger,
    )
  end
  let(:logger) { instance_double(ActiveSupport::Logger, warn: nil) }

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

  describe 'when a refresh fails' do
    before do
      cache.key_for(issuer, kid)
      advance(described_class::LIFESPAN_SECONDS)
      responses << Net::OpenTimeout
    end

    it 'serves the expired set and logs a warning' do
      expect(cache.key_for(issuer, kid)).to be_a(OpenSSL::PKey::RSA)
      expect(logger).to have_received(:warn).with(a_string_including('JWKS fetch', 'Net::OpenTimeout'))
    end

    it 'keeps serving the expired set during the backoff without refetching' do
      2.times { cache.key_for(issuer, kid) }
      expect(fetches.size).to eq(2)
    end

    it 'refuses once the set is older than the grace period' do
      advance(described_class::STALE_GRACE_SECONDS - described_class::LIFESPAN_SECONDS)
      expect { cache.key_for(issuer, kid) }.to raise_error(described_class::Unavailable)
    end
  end

  describe 'concurrency' do
    let(:release)  { Queue.new }
    let(:started)  { Queue.new }
    let(:calls)    { [] }
    let(:blocking_cache) do
      described_class.new(
        fetcher: lambda { |url|
          calls << url
          if url.include?('slow')
            started << true
            release.pop
          end
          mpass_jwks_document
        },
        logger:  logger,
      )
    end

    after { release << true while release.num_waiting.positive? }

    it 'does not block other issuers while one fetch is in flight' do
      slow = Thread.new { blocking_cache.key_for('https://slow.example.test', kid) }
      started.pop
      expect(blocking_cache.key_for(issuer, kid)).to be_a(OpenSSL::PKey::RSA)
      release << true
      expect(slow.value).to be_a(OpenSSL::PKey::RSA)
    end

    it 'fetches an issuer once when several threads ask at the same time' do
      first = Thread.new { blocking_cache.key_for('https://slow.example.test', kid) }
      started.pop
      waiters = Array.new(3) { Thread.new { blocking_cache.key_for('https://slow.example.test', kid) } }
      Thread.pass until waiters.all? { |thread| thread.status == 'sleep' }
      release << true
      expect([first, *waiters].map(&:value)).to all(be_a(OpenSSL::PKey::RSA))
      expect(calls.count { |url| url.include?('slow') }).to eq(1)
    end
  end
end
