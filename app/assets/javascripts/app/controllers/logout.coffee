class Logout
  constructor: ->

    # Under platform SSO the per-app sign out is navigation only: it returns the
    # user to the platform portal and must not clear any session. The actual sign
    # out happens at the portal ("Logout all"). Clearing the local session here
    # would achieve nothing anyway, because the mPass proxy auth middleware
    # re-establishes it from the X-Auth-Request-Email header on the next request.
    if App.Config.get('mpass_sso_active')
      redirectUrl = App.Config.get('mpass_logout_redirect_url')
      if !redirectUrl
        App.Log.error('Auth', 'platform SSO is active but no logout redirect URL is configured, staying put')
        return
      window.location.href = redirectUrl
      return

    App.Auth.logout()

App.Config.set('logout', Logout, 'Routes')
App.Config.set('Logout', { prio: 1800, parent: '#current_user', name: __('Sign out'), translate: true, target: '#logout', divider: true, iconClass: 'signout' }, 'NavBarRight')
