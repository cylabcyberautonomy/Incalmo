import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  IconButton,
  LinearProgress,
  Stack,
  Tooltip,
  Typography,
} from '@mui/material';
import { Refresh } from '@mui/icons-material';

import { LiteLLMUsage, OpenRouterUsage } from '../hooks/useApiUsage';

interface ApiUsageMonitorProps {
  openrouter: OpenRouterUsage | null;
  litellm: LiteLLMUsage | null;
  loading: boolean;
  error: string | null;
  lastFetched: Date | null;
  onRefresh: () => void;
}

const formatUsd = (value: number | null | undefined): string =>
  value === null || value === undefined ? '—' : `$${value.toFixed(4)}`;

const formatAge = (epochSeconds: number | null): string => {
  if (epochSeconds === null) return '';
  const ageMs = Date.now() - epochSeconds * 1000;
  const ageMin = Math.floor(ageMs / 60000);
  if (ageMin < 1) return 'just now';
  if (ageMin < 60) return `${ageMin}m ago`;
  return `${Math.floor(ageMin / 60)}h ${ageMin % 60}m ago`;
};

const sourceLabel: Record<LiteLLMUsage['source'], { text: string; color: 'success' | 'warning' | 'default' }> = {
  key_info: { text: 'Live', color: 'success' },
  last_call_headers: { text: 'From last call', color: 'warning' },
  unavailable: { text: 'Unavailable', color: 'default' },
};

const ApiUsageMonitor: React.FC<ApiUsageMonitorProps> = ({
  openrouter,
  litellm,
  loading,
  error,
  lastFetched,
  onRefresh,
}) => {
  return (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column', gap: 2, p: 1, overflow: 'auto' }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="subtitle2" color="text.secondary">
          {lastFetched ? `Updated ${lastFetched.toLocaleTimeString()}` : 'Not yet fetched'}
        </Typography>
        <Tooltip title="Refresh now">
          <IconButton size="small" onClick={onRefresh} disabled={loading}>
            <Refresh fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>

      {error && (
        <Typography variant="body2" color="error">
          {error}
        </Typography>
      )}

      {/* OpenRouter */}
      <Card variant="outlined">
        <CardContent>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="subtitle1">OpenRouter</Typography>
            {openrouter?.error && <Chip label="Error" color="error" size="small" />}
          </Stack>
          {openrouter?.error ? (
            <Typography variant="body2" color="error">
              {openrouter.error}
            </Typography>
          ) : (
            <Stack spacing={1}>
              <Typography variant="body2">
                Usage: <strong>{formatUsd(openrouter?.usage)}</strong>
                {openrouter?.limit !== null && openrouter?.limit !== undefined && (
                  <> / {formatUsd(openrouter.limit)}</>
                )}
              </Typography>
              {openrouter?.usage !== null &&
                openrouter?.usage !== undefined &&
                openrouter?.limit !== null &&
                openrouter?.limit !== undefined &&
                openrouter.limit > 0 && (
                  <LinearProgress
                    variant="determinate"
                    value={Math.min(100, (openrouter.usage / openrouter.limit) * 100)}
                    color={openrouter.usage / openrouter.limit > 0.9 ? 'error' : 'primary'}
                  />
                )}
              {(openrouter?.limit === null || openrouter?.limit === undefined) && (
                <Typography variant="caption" color="text.secondary">
                  No credit limit set on this key.
                </Typography>
              )}
            </Stack>
          )}
        </CardContent>
      </Card>

      {/* LiteLLM */}
      <Card variant="outlined">
        <CardContent>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="subtitle1">LiteLLM (CMU gateway)</Typography>
            {litellm && (
              <Chip
                label={sourceLabel[litellm.source].text}
                color={sourceLabel[litellm.source].color}
                size="small"
              />
            )}
          </Stack>
          {litellm?.source === 'unavailable' ? (
            <Typography variant="body2" color="text.secondary">
              {litellm.error ?? 'No data available yet.'}
            </Typography>
          ) : (
            <Stack spacing={1}>
              <Typography variant="body2">
                Spend: <strong>{formatUsd(litellm?.spend)}</strong>
                {litellm?.max_budget !== null && litellm?.max_budget !== undefined && (
                  <> / {formatUsd(litellm.max_budget)}</>
                )}
              </Typography>
              {litellm?.spend !== null &&
                litellm?.spend !== undefined &&
                litellm?.max_budget !== null &&
                litellm?.max_budget !== undefined &&
                litellm.max_budget > 0 && (
                  <LinearProgress
                    variant="determinate"
                    value={Math.min(100, (litellm.spend / litellm.max_budget) * 100)}
                    color={litellm.spend / litellm.max_budget > 0.9 ? 'error' : 'primary'}
                  />
                )}
              {litellm?.source === 'last_call_headers' && (
                <Typography variant="caption" color="text.secondary">
                  As of {formatAge(litellm.as_of)} — no admin key configured, showing the totals from
                  the last actual LLM call through this key. Set LITELLM_ADMIN_KEY for a live figure
                  that updates even when idle.
                </Typography>
              )}
              {litellm?.error && (
                <Typography variant="caption" color="error">
                  {litellm.error}
                </Typography>
              )}
            </Stack>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default ApiUsageMonitor;
