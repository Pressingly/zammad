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
    STALE_GRACE_SECONDS     = 24 * 3600

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

    def initialize(fetcher: self.class.method(:http_fetch), clock: self.class.method(:monotonic_now), logger: Rails.logger)
      @fetcher   = fetcher
      @clock     = clock
      @logger    = logger
      @entries   = {}
      @failed_at = {}
      @in_flight = Set.new
      @mutex     = Mutex.new
      @fetched   = ConditionVariable.new
    end

    # The issuer's key for kid. A cached set lacking kid is refetched at most
    # once per refresh interval, so a Cognito key rotation is picked up without a restart.
    def key_for(issuer, kid)
      jwk = find_key(usable_set(issuer, max_age: LIFESPAN_SECONDS), kid) ||
            find_key(usable_set(issuer, max_age: MIN_REFRESH_INTERVAL), kid)
      jwk&.verify_key
    end

    private

    def find_key(set, kid)
      set.find { |jwk| jwk[:kid] == kid }
    end

    # The network fetch runs outside the lock: one thread fetches per issuer,
    # the others serve the stale set meanwhile, or wait when there is none.
    def usable_set(issuer, max_age:)
      action, entry = @mutex.synchronize { plan(issuer, max_age) }
      case action
      when :use   then entry[:set]
      when :stale then stale_set(entry)
      else fetch_and_store(issuer)
      end
    end

    def plan(issuer, max_age)
      @fetched.wait(@mutex) while @in_flight.include?(issuer) && @entries[issuer].nil?

      entry = @entries[issuer]
      return [:use, entry] if entry && age(entry) < max_age
      return [:stale, entry] if @in_flight.include?(issuer) || recently_failed?(issuer)

      @in_flight << issuer
      [:fetch, entry]
    end

    def fetch_and_store(issuer)
      set = load_set(issuer)
      @mutex.synchronize { @entries[issuer] = { set: set, fetched_at: @clock.call } }
      set
    rescue => e
      @logger.warn("mpass_jwks_cache: JWKS fetch for #{issuer} failed (#{e.class.name}); serving the cached set if it is within the grace period")
      stale_set(@mutex.synchronize do
        @failed_at[issuer] = @clock.call
        @entries[issuer]
      end)
    ensure
      @mutex.synchronize do
        @in_flight.delete(issuer)
        @fetched.broadcast
      end
    end

    def stale_set(entry)
      raise Unavailable, 'no usable JWKS' if entry.nil? || age(entry) >= STALE_GRACE_SECONDS

      entry[:set]
    end

    def load_set(issuer)
      document = JSON.parse(@fetcher.call(self.class.jwks_url(issuer)))
      raise Unavailable, 'JWKS document has no keys' if !document.is_a?(Hash) || !document['keys'].is_a?(Array)

      JWT::JWK::Set.new(document)
    end

    def age(entry)
      @clock.call - entry[:fetched_at]
    end

    def recently_failed?(issuer)
      failed_at = @failed_at[issuer]
      !failed_at.nil? && @clock.call - failed_at < FAILURE_BACKOFF_SECONDS
    end
  end
end
