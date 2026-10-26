import { beforeEach, describe, expect, it, vi } from 'vitest'
import { initMainSiteAuth } from '../mainSiteAuth'

function authResponse() {
  return {
    access_token: 'sub2api-access',
    refresh_token: 'sub2api-refresh',
    expires_in: 3600,
    token_type: 'Bearer',
    user: {
      id: 1,
      email: 'main@example.com',
      username: 'main-user',
      role: 'user',
      status: 'active',
      balance: 0,
      concurrency: 1,
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-01T00:00:00Z'
    }
  }
}

describe('initMainSiteAuth', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    window.history.replaceState({}, '', '/?foo=1&parent_token=main-site-token&parent_username=main-user')
  })

  it('exchanges parent_token with parent_username and removes both from the URL', async () => {
    const store = {
      isAuthenticated: false,
      checkAuth: vi.fn(),
      loginWithMainSite: vi.fn().mockResolvedValue(authResponse())
    }

    await initMainSiteAuth(store as never)

    expect(store.loginWithMainSite).toHaveBeenCalledWith('main-site-token', 'main-user')
    expect(window.location.search).toBe('?foo=1')
  })

  it('exchanges a fragment handoff without leaving the token in the URL', async () => {
    window.history.replaceState({}, '', '/#parent_token=fragment-token&parent_username=fragment-user')
    const store = {
      isAuthenticated: false,
      checkAuth: vi.fn(),
      loginWithMainSite: vi.fn().mockResolvedValue(authResponse())
    }

    await initMainSiteAuth(store as never)

    expect(store.loginWithMainSite).toHaveBeenCalledWith('fragment-token', 'fragment-user')
    expect(window.location.hash).toBe('')
  })
})
