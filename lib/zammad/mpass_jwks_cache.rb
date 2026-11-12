# Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

require 'json'
require 'jwt'
require 'net/http'

module Zammad
  class MpassJwksCache
    LIFESPAN_SECONDS        = 3600
    FETCH_TIMEOUT_SECONDS   = 2
    FAILURE_BACKOFF_SECONDS = 30
    MIN_REFRESH_INTERVAL    = 30

    class Unavailable < StandardError; end

    def self.jwks_url(issuer)
      "#{issuer.chomp('/')}/.well-known/jwks.json"
    end

    def self.http_fetch(url)
      uri = URI.parse(url)
      response = Net::HTTP.start(uri.host, uri.port,
                                 use_ssl:      uri.scheme == 'https',
                                 open_timeout: FETCH_TIMEOUT_SECONDS,
                                 read_timeout: FETCH_TIMEOUT_SECONDS) do |http|
        http.get(uri.request_uri)
      end
      raise Unavailable, "HTTP #{response.code}" if !response.is_a?(Net::HTTPSuccess)

      response.body
    end

    def self.monotonic_now
      Process.clock_gettime(Process::CLOCK_MONOTONIC)
    end

    def initialize(fetcher: self.class.method(:http_fetch), clock: self.class.method(:monotonic_now))
      @fetcher = fetcher
      @clock   = clock
      @entries = {}
      @failed_at = {}
      @mutex = Mutex.new
    end

    # The issuer's key for kid, refetching once (rate limited) when the cached
    # set lacks it, so a Cognito key rotation is picked up without a restart.
    def key_for(issuer, kid)
      @mutex.synchronize do
        jwk = find_key(cached_set(issuer), kid)
        jwk ||= find_key(refreshed_set(issuer), kid) if refresh_allowed?(issuer)
        jwk&.verify_key
      end
    end

    private

    def find_key(set, kid)
      set.find { |jwk| jwk[:kid] == kid }
    end

    def cached_set(issuer)
      entry = @entries[issuer]
      return entry[:set] if entry && @clock.call - entry[:fetched_at] < LIFESPAN_SECONDS

      refreshed_set(issuer)
    end

    def refresh_allowed?(issuer)
      entry = @entries[issuer]
      entry.nil? || @clock.call - entry[:fetched_at] >= MIN_REFRESH_INTERVAL
    end

    def refreshed_set(issuer)
      raise Unavailable, 'recent JWKS fetch failure' if recently_failed?(issuer)

      fetch_and_store(issuer)
    end

    def fetch_and_store(issuer)
      set = load_set(issuer)
      @entries[issuer] = { set: set, fetched_at: @clock.call }
      set
    rescue => e
      @failed_at[issuer] = @clock.call
      raise Unavailable, e.class.name
    end

    def load_set(issuer)
      document = JSON.parse(@fetcher.call(self.class.jwks_url(issuer)))
      raise Unavailable, 'JWKS document has no keys' if !document.is_a?(Hash) || !document['keys'].is_a?(Array)

      JWT::JWK::Set.new(document)
    end

    def recently_failed?(issuer)
      failed_at = @failed_at[issuer]
      !failed_at.nil? && @clock.call - failed_at < FAILURE_BACKOFF_SECONDS
    end
  end
end
