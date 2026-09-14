// Copyright (C) 2012-2026 Zammad Foundation, https://zammad-foundation.org/

import { useApplicationStore } from '#shared/stores/application.ts'

import log from './log.ts'

/**
 * Handle the per-app sign out under platform SSO.
 *
 * Under platform SSO the per-app sign out is navigation only: it returns the user to the
 * platform portal and must not clear any session — the actual sign out happens at the portal
 * ("Logout all"). Clearing the local session would achieve nothing anyway, because the mPass
 * proxy auth middleware re-establishes it from the `X-Auth-Request-Email` header on the next
 * request.
 *
 * The portal URL is supplied by the deployment environment and exposed as a frontend setting,
 * it is never derived from the current host.
 *
 * @returns `true` when the caller must not continue with the regular logout.
 */
export const handleMpassLogout = (): boolean => {
  const application = useApplicationStore()

  if (application.config.mpass_sso_active !== true) return false

  const redirectUrl = application.config.mpass_logout_redirect_url

  if (typeof redirectUrl !== 'string' || redirectUrl === '') {
    log.error('Platform SSO is active, but no logout redirect URL is configured.')
    return true
  }

  window.location.href = redirectUrl

  return true
}
