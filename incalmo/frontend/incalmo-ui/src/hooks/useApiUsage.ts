import { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8888';
const POLL_INTERVAL_MS = 30000;

export interface OpenRouterUsage {
  // From OpenRouter's self-serve /api/v1/key: this key's own spend cap (the
  // "Credit limit" field on OpenRouter's key-edit page), not the account-wide
  // lifetime-purchased-credits figure /api/v1/credits returns. null = no limit set.
  limit: number | null;
  limit_remaining: number | null;
  usage: number | null;
  error: string | null;
}

export interface LiteLLMUsage {
  spend: number | null;
  max_budget: number | null;
  // 'key_info': live admin-key lookup, accurate even when idle.
  // 'last_call_headers': best-effort, only as fresh as the most recent actual call.
  // 'unavailable': neither an admin key nor any observed call exists yet.
  source: 'key_info' | 'last_call_headers' | 'unavailable';
  as_of: number | null; // epoch seconds; null for a live 'key_info' read
  error: string | null;
}

interface ApiUsage {
  openrouter: OpenRouterUsage;
  litellm: LiteLLMUsage;
}

// Live-monitors the OPENROUTER_API_KEY / LITELLM_API_KEY that Incalmo itself is
// configured with - see incalmo/c2server/routes/usage_routes.py for the sources.
export const useApiUsage = () => {
  const [usage, setUsage] = useState<ApiUsage | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [lastFetched, setLastFetched] = useState<Date | null>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchUsage = useCallback(async () => {
    setLoading(true);
    try {
      const response = await axios.get<ApiUsage>(`${API_BASE_URL}/get_api_usage`, { timeout: 15000 });
      setUsage(response.data);
      setError(null);
      setLastFetched(new Date());
    } catch (err) {
      const message = axios.isAxiosError(err) ? err.message : 'Failed to fetch API usage';
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsage();
    intervalRef.current = setInterval(fetchUsage, POLL_INTERVAL_MS);
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [fetchUsage]);

  return { usage, loading, error, lastFetched, refresh: fetchUsage };
};
