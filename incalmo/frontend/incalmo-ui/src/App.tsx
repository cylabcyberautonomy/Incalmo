import React, {useState} from 'react';
import { Container, Paper, Box, Divider, Tab, Tabs, Typography } from '@mui/material';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

import { darkTheme } from './themes/theme';
import { useIncalmoApi } from './hooks/interfaceIncalmoApi';
import { useApiUsage } from './hooks/useApiUsage';
import Header from './components/Header';
import StrategyLauncher from './components/StrategyLauncher';
import RunningStrategies from './components/RunningStrategies';
import ConnectedAgents from './components/ConnectedAgents';
import NetworkGraph from './components/NetworkGraph';
import ActionLogs from './components/ActionLogs';
import LLMLogs from './components/LLMLogs';
import TimelineGraph from './components/TimelineGraph';
import ApiUsageMonitor from './components/ApiUsageMonitor';

const App = () => {

  const [selectedGraphTab, setSelectedGraphTab] = useState(0);
  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setSelectedGraphTab(newValue);
  };

  const {
    selectedStrategy,
    loading,
    message,
    messageType,
    agents,
    runningStrategies,
    strategies,
    hosts,
    hostsLoading,
    hostsError,
    lastHostsUpdate,
    lowLevelLogs,
    highLevelLogs,
    actionStreamConnected,
    actionStreamError,
    llmLogs,
    llmStreamConnected,
    llmStreamError,
    fetchHosts,
    deleteAgent,
    sendCommandToAgent,
    setSelectedStrategy,
    startStrategy,
    stopStrategy,
    fetchRunningStrategies,
    getStatusColor
  } = useIncalmoApi();

  const {
    usage: apiUsage,
    loading: apiUsageLoading,
    error: apiUsageError,
    lastFetched: apiUsageLastFetched,
    refresh: refreshApiUsage
  } = useApiUsage();

  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <div className="App">
        <Header agentCount={Object.keys(agents).length} />

        <Container
          disableGutters
          maxWidth={false}
          sx={{
            height: 'calc(87vh)',
            px: 2,
            mt: 2,
            mb: 2
          }}
        >
          <Box sx={{
            display: 'flex',
            gap: 2,
            height: '100%'
          }}>
            {/* Left Panel - Strategy Controls */}
            <Box sx={{ width: '20%', flexShrink: 0 }}>
              <Paper sx={{
                p: 2,
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                bgcolor: 'background.paper',
                borderRadius: 2,
                overflow: 'hidden'
              }}>
                <Box sx={{ mb: 2 }}>
                  <StrategyLauncher
                    selectedStrategy={selectedStrategy}
                    setSelectedStrategy={setSelectedStrategy}
                    strategies={strategies}
                    loading={loading}
                    startStrategy={startStrategy}
                    fetchRunningStrategies={fetchRunningStrategies}
                    message={message}
                    messageType={messageType}
                  />
                </Box>

                <Box sx={{ flex: 1, overflow: 'auto' }}>
                  <RunningStrategies
                    runningStrategies={runningStrategies}
                    stopStrategy={stopStrategy}
                    getStatusColor={getStatusColor}
                  />
                </Box>
              </Paper>
            </Box>

            {/* Center Panel - Network Visualization */}
            <Box sx={{ width: '50%', flexShrink: 0 }}>
              <Paper sx={{
                p: 2,
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                bgcolor: 'background.paper',
                borderRadius: 2,
                overflow: 'hidden'
              }}>
                <Box sx={{
                  height: '65%',
                  mb: 2,
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column'
                }}>
                  <Tabs
                    value={selectedGraphTab}
                    onChange={handleTabChange}
                    sx={{ mb: 1 }}
                  >
                    <Tab label="Network Graph" />
                    <Tab label="Timeline" />
                    <Tab label="API Usage" />
                  </Tabs>
                  {selectedGraphTab === 0 ? (
                      <NetworkGraph
                        hosts={hosts}
                        loading={hostsLoading}
                        error={hostsError}
                        lastUpdate={lastHostsUpdate}
                        onRefresh={fetchHosts}
                      />
                    ) : selectedGraphTab === 1 ? (
                        <TimelineGraph
                          highLevelLogs={highLevelLogs}
                          lowLevelLogs={lowLevelLogs}
                        />
                    ) : (
                        <ApiUsageMonitor
                          openrouter={apiUsage?.openrouter ?? null}
                          litellm={apiUsage?.litellm ?? null}
                          loading={apiUsageLoading}
                          error={apiUsageError}
                          lastFetched={apiUsageLastFetched}
                          onRefresh={refreshApiUsage}
                        />
                    )}
                </Box>

                <Box sx={{
                  height: '35%',
                  overflow: 'hidden',
                  display: 'flex',
                  flexDirection: 'column'
                }}>
                  <ConnectedAgents agents={agents} deleteAgent={deleteAgent} sendCommandToAgent={sendCommandToAgent} />
                </Box>
              </Paper>
            </Box>

            {/* Right Panel - Logs */}
            <Box sx={{ width: '28%', flexShrink: 0 }}>
              <Paper sx={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                bgcolor: 'background.paper',
                borderRadius: 2,
                overflow: 'hidden'
              }}>
                <Box sx={{ height: '50%', overflow: 'hidden' }}>
                  <ActionLogs
                    logs={lowLevelLogs}
                    isConnected={actionStreamConnected}
                    error={actionStreamError}
                  />
                </Box>
                <Divider />
                <Box sx={{ height: '50%', overflow: 'hidden' }}>
                  <LLMLogs
                    logs={llmLogs}
                    isConnected={llmStreamConnected}
                    error={llmStreamError}
                  />
                </Box>
              </Paper>
            </Box>
          </Box>
        </Container>
      </div>
    </ThemeProvider>
  );
};

export default App;