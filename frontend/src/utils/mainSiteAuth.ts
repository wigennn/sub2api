import type { LoginResponse } from '@/api/auth'
import { buildApiUrl } from '@/api/url'

const READY_MESSAGE_TYPE = 'TUTU_APP_READY'
const AUTH_MESSAGE_TYPE = 'AUTH_TOKEN'
const TOTP_STORAGE_KEY = 'main_site_2fa'

interface AuthStore {
  checkAuth(): void
  isAuthenticated: boolean
  loginWithMainSite(accessToken?: string, username?: string): Promise<LoginResponse>
}

interface MainSiteHandoff {
  token: string
  username: string
}

function trustedParentOrigins(): string[] {
  const origins = new Set<string>()
  if (window.location.ancestorOrigins?.length) {
    origins.add(window.location.ancestorOrigins[0])
  }
  if (document.referrer) {
    try {
      origins.add(new URL(document.referrer).origin)
    } catch {
      // Ignore malformed referrers.
    }
  }
  return [...origins]
}

function consumeHandoffFromURL(): MainSiteHandoff {
  const params = new URLSearchParams(window.location.search)
  const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ''))
  const token = params.get('parent_token') || params.get('token') ||
    fragment.get('parent_token') || fragment.get('token')
  const username = params.get('parent_username') || fragment.get('parent_username')

  params.delete('parent_token')
  params.delete('token')
  params.delete('parent_username')
  fragment.delete('parent_token')
  fragment.delete('token')
  fragment.delete('parent_username')
  const query = params.toString()
  const hash = fragment.toString()
  window.history.replaceState(
    null,
    '',
    `${window.location.pathname}${query ? `?${query}` : ''}${hash ? `#${hash}` : ''}`
  )
  return {
    token: token?.trim() || '',
    username: username?.trim() || ''
  }
}

export function startMainSiteLogin(): void {
  window.location.assign(buildApiUrl('/auth/main-site/start'))
}

function waitForParentToken(timeoutMs: number): Promise<MainSiteHandoff> {
  return new Promise((resolve) => {
    const origins = trustedParentOrigins()
    let settled = false
    const finish = (handoff: MainSiteHandoff) => {
      if (settled) return
      settled = true
      window.removeEventListener('message', onMessage)
      resolve(handoff)
    }
    const onMessage = (event: MessageEvent) => {
      if (event.source !== window.parent) return
      if (origins.length && !origins.includes(event.origin)) return
      if (event.data?.type !== AUTH_MESSAGE_TYPE) return
      if (typeof event.data.token !== 'string' || !event.data.token.trim()) return
      finish({
        token: event.data.token.trim(),
        username: typeof event.data.username === 'string' ? event.data.username.trim() : ''
      })
    }

    window.addEventListener('message', onMessage)
    const readyTarget = origins.length === 1 ? origins[0] : '*'
    window.parent.postMessage({ type: READY_MESSAGE_TYPE, app: 'sub2api' }, readyTarget)
    window.setTimeout(() => finish({ token: '', username: '' }), timeoutMs)
  })
}

function persistTwoFactorChallenge(response: LoginResponse): void {
  if (!('requires_2fa' in response) || !response.requires_2fa) return
  sessionStorage.setItem(TOTP_STORAGE_KEY, JSON.stringify({
    temp_token: response.temp_token,
    user_email_masked: response.user_email_masked
  }))
}

export async function initMainSiteAuth(authStore: AuthStore): Promise<void> {
  authStore.checkAuth()
  let handoff = consumeHandoffFromURL()
  if (!handoff.token && authStore.isAuthenticated) return
  if (!handoff.token && window.self !== window.top) {
    handoff = await waitForParentToken(2500)
  }
  if (!handoff.token) return

  try {
    const response = await authStore.loginWithMainSite(handoff.token, handoff.username)
    persistTwoFactorChallenge(response)
  } catch (error) {
    console.warn('Main-site login exchange failed:', error)
  }
}

export function consumeMainSiteTwoFactorChallenge(): {
  temp_token?: string
  user_email_masked?: string
} | null {
  const raw = sessionStorage.getItem(TOTP_STORAGE_KEY)
  sessionStorage.removeItem(TOTP_STORAGE_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as { temp_token?: string; user_email_masked?: string }
  } catch {
    return null
  }
}
